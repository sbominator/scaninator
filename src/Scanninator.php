<?php

namespace Scanninator;

use PhpParser\ParserFactory;

/**
 * Scanninator
 *
 * This class scans PHP files for dependencies (require/include statements)
 * and resolves their full paths. It can scan local files or download and scan
 * files from GitHub repositories.
 */
class Scanninator
{
    /**
     * PHP Parser instance
     *
     * @var PhpParser\Parser
     */
    private $parser;

    /**
     * Main file to scan
     *
     * @var string
     */
    private $filename;

    /**
     * Temporary directory for cloned repositories
     *
     * @var string
     */
    private $tmpDir;

    /**
     * Flag to indicate if we're working with a GitHub URL
     *
     * @var boolean
     */
    private $isGithubUrl = false;

    /**
     * GitHub URL
     *
     * @var string
     */
    private $githubUrl;

    /**
     * Software Bill of Materials (SBOM) data
     *
     * @var array
     */
    private $sbom = null;

    /**
     * List of dependencies
     *
     * @var array
     */
    private $dependencies = [];

    /**
     * List of packages
     *
     * @var array
     */
    private $packages = [];

    /**
     * Debug mode flag
     *
     * @var boolean
     */
    private $debugMode = false;

    /**
     * Flag to indicate if auto-cleanup is registered
     *
     * @var boolean
     */
    private static $autoCleanupRegistered = false;

    /**
     * Constructor
     *
     * @param string $input The PHP file to analyze or a GitHub URL.
     */
    public function __construct($input)
    {
        $this->debugMode = (php_sapi_name() === 'cli');
        $this->checkDependencies();

        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();

        if ($this->isGithubUrl($input)) {
            $this->isGithubUrl = true;
            $this->githubUrl = $input;
        } else {
            $this->filename = $input;
        }
    }

    /**
     * Register cleanup function to run on shutdown
     *
     * @return void
     */
    private function registerAutoCleanup()
    {
        if (!self::$autoCleanupRegistered) {
            // Store instance in a static variable to access it in the shutdown function.
            static $instance = null;
            $instance = $this;

            register_shutdown_function(
                function () use ($instance) {
                    $instance->cleanup();
                }
            );

            self::$autoCleanupRegistered = true;
        }
    }

    /**
     * Output debug message when in CLI mode
     *
     * @param string $message The message to output.
     * @return void
     */
    private function debug($message)
    {
        if ($this->debugMode) {
            echo $message . PHP_EOL;
        }
    }

    /**
     * Check if required dependencies are installed
     *
     * @return void
     * @throws \Exception When a dependency is missing.
     */
    private function checkDependencies()
    {
        $requiredExtensions = ['tokenizer'];

        foreach ($requiredExtensions as $ext) {
            if (!extension_loaded($ext)) {
                throw new \Exception("The '{$ext}' extension is required for this script to run.");
            }
        }

        $commands = ['git'];

        foreach ($commands as $command) {
            if (!shell_exec('command -v ' . $command)) {
                throw new \Exception("The '{$command}' command is required for this script to run.");
            }
        }
    }

    /**
     * Fetch SBOM data from GitHub
     *
     * @return array|null SBOM data or null if not available
     * @throws \Exception When GitHub URL is invalid.
     */
    public function getSbom()
    {
        if (!$this->isGithubUrl) {
            return null;
        }

        $owner = '';
        $repo = '';

        $urlParts = parse_url($this->githubUrl);
        $pathParts = explode('/', trim($urlParts['path'], '/'));

        if (count($pathParts) > 1) {
            $owner = $pathParts[0];
            $repo = $pathParts[1];
        }

        if (empty($owner) || empty($repo)) {
            throw new \Exception('Invalid GitHub URL format.');
        }

        $sbomUrl = 'https://api.github.com/repos/' . $owner . '/' . $repo . '/dependency-graph/sbom';

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $sbomUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Scanninator');
        $output = curl_exec($ch);
        curl_close($ch);

        $sbom = json_decode($output, true);

        if (is_array($sbom)) {
            $this->sbom = $sbom;
        }

        return $this->sbom;
    }

    /**
     * Check if the input is a GitHub URL
     *
     * @param string $url The URL to check.
     * @return boolean True if the URL is a GitHub URL.
     */
    private function isGithubUrl($url)
    {
        return preg_match('/^https?:\/\/github\.com\//', $url) === 1;
    }

    /**
     * Setup a GitHub repository for scanning
     *
     * @param string $githubUrl The GitHub URL.
     * @return string The path to the file to scan.
     * @throws \Exception When repository cannot be accessed.
     */
    private function setupGithubRepo($githubUrl)
    {
        // Create tmp directory if it doesn't exist.
        $baseTmpDir = __DIR__ . '/tmp';
        if (!file_exists($baseTmpDir)) {
            mkdir($baseTmpDir, 0755, true);
        }

        // Parse GitHub URL.
        $urlParts = parse_url($githubUrl);
        $pathParts = explode('/', trim($urlParts['path'], '/'));

        // Extract repo owner and name.
        $owner = $pathParts[0];
        $repo = $pathParts[1];

        // Create a unique temp directory for this repo.
        $repoDir = $baseTmpDir . '/' . $owner . '_' . $repo . '_' . time();
        mkdir($repoDir, 0755, true);
        $this->tmpDir = $repoDir;

        // Clone the repository.
        $cloneUrl = 'https://github.com/' . escapeshellarg(trim($owner)) . '/' . escapeshellarg(trim($repo)) . '.git';
        $escapedRepoDir = escapeshellarg($repoDir);
        exec("git clone {$cloneUrl} {$escapedRepoDir}");

        // Determine file path within repo.
        $filePath = '';
        if (count($pathParts) > 4 && $pathParts[2] === 'blob') {
            // Format: github.com/owner/repo/blob/branch/path/to/file.php.
            $branch = $pathParts[3];
            $filePath = $repoDir . '/' . implode('/', array_slice($pathParts, 4));
        } else {
            throw new \Exception('Invalid GitHub URL format.');
        }

        // Check if file exists
        if (!file_exists($filePath)) {
            throw new \Exception('File not found in repository.');
        }

        return $filePath;
    }

    /**
     * Cleanup temporary files when done
     *
     * @return void
     */
    public function cleanup()
    {
        if ($this->isGithubUrl && $this->tmpDir && file_exists($this->tmpDir)) {
            $this->debug('Cleaning up temporary files in: ' . $this->tmpDir);
            $this->deleteDirectory($this->tmpDir);
        }
    }

    /**
     * Recursively delete a directory
     *
     * @param string $dir Directory path to delete
     * @return bool True on success, false on failure
     */
    private function deleteDirectory($dir)
    {
        if (!is_dir($dir)) {
            return false;
        }

        $files = array_diff(scandir($dir), ['.', '..']);

        foreach ($files as $file) {
            $path = $dir . '/' . $file;

            if (is_dir($path)) {
                $this->deleteDirectory($path);
            } else {
                unlink($path);
            }
        }

        return rmdir($dir);
    }

    /**
     * Run the dependency scan
     *
     * @return array The list of dependencies
     */
    public function scan()
    {
        if ($this->isGithubUrl) {
            $this->filename = $this->setupGithubRepo($this->githubUrl);
            $this->getSbom();
            $this->registerAutoCleanup();
        }

        $stmts = $this->parser->parse(file_get_contents($this->filename));
        return $this->getRequires($stmts, $this->filename);
    }

    /**
     * Get all required files from the statements
     *
     * @param array  $stmts    The parsed PHP statements.
     * @param string $mainFile The file containing the statements.
     * @return array List of required files with full paths
     */
    public function getRequires($stmts, $mainFile)
    {
        $requires = [];
        $baseDir = dirname($mainFile);

        foreach ($stmts as $stmt) {
            // Handle namespaced code
            if ($stmt instanceof \PhpParser\Node\Stmt\Namespace_ && !empty($stmt->stmts)) {
                // Recursively scan statements within the namespace
                $namespaceRequires = $this->getRequires($stmt->stmts, $mainFile);
                $requires = array_merge($requires, $namespaceRequires);
                continue;
            }

            $expr = null;

            if ($stmt instanceof \PhpParser\Node\Expr\Include_) {
                $expr = $stmt->expr;
            } elseif ($stmt instanceof \PhpParser\Node\Stmt\Expression) {
                if ($stmt->expr instanceof \PhpParser\Node\Expr\Include_) {
                    $expr = $stmt->expr->expr;
                }
            }

            if (!empty($expr)) {
                $requiredFile = '';

                // Handle concatenation with __DIR__ and other constants.
                if ($expr instanceof \PhpParser\Node\Expr\BinaryOp\Concat) {
                    $leftPart = $expr->left;
                    $rightPart = $expr->right;

                    // Handle __DIR__ . '/something/file.php'.
                    if ($leftPart instanceof \PhpParser\Node\Scalar\MagicConst\Dir) {
                        if ($rightPart instanceof \PhpParser\Node\Scalar\String_) {
                            // Use dirname() directly instead of concatenating paths that may already contain the repo path.
                            $requiredFile = dirname($mainFile) . $rightPart->value;
                        }
                    } else { // Handle other cases.
                        // Try to extract a path if possible
                        if ($rightPart instanceof \PhpParser\Node\Scalar\String_) {
                            $rightValue = $rightPart->value;

                            if (isset($expr->left->value)) {
                                $requiredFile = $expr->left->value . $rightValue;
                            } else {
                                $requiredFile = $rightValue;
                            }
                        }
                    }
                } elseif ($expr instanceof \PhpParser\Node\Scalar\String_) {
                    $requiredFile = $expr->value;
                } else {
                    $requiredFile = $expr->getAttribute('rawValue', '');

                    // Clean up quotes if present.
                    $requiredFile = str_replace("'", '', $requiredFile);
                    $requiredFile = str_replace('"', '', $requiredFile);
                }

                if (empty($requiredFile)) {
                    continue;
                }

                $this->debug('Found require: ' . $requiredFile);

                // Determine the full path.
                $fullPath = '';
                if (strpos($requiredFile, '/') === 0) {
                    // Absolute path.
                    $fullPath = $requiredFile;
                } elseif (isset($this->tmpDir) && strpos($requiredFile, $this->tmpDir) === 0) {
                    // Already contains the full repo path.
                    $fullPath = $requiredFile;
                } else {
                    // Relative path.
                    $fullPath = $baseDir . '/' . $requiredFile;
                }

                // Resolve path (handles .. and . in paths).
                $resolvedPath = realpath($fullPath);

                $requires[] = [
                    'original' => $requiredFile,
                    'full_path' => $resolvedPath ? $resolvedPath : $fullPath,
                ];
            }
        }

        // Track processed files to avoid infinite recursion.
        static $processedFiles = [];

        foreach ($requires as $require) {
            $requiredFile = $require['full_path'];

            // Skip if already processed.
            if (in_array($requiredFile, $processedFiles, true)) {
                continue;
            }

            $processedFiles[] = $requiredFile;

            if (!file_exists($requiredFile) || is_dir($requiredFile)) {
                $this->debug('File does not exist: ' . $requiredFile);
                continue;
            }

            $requiredStmts = $this->parser->parse(file_get_contents($requiredFile));

            $this->debug('Scanning: ' . $requiredFile);

            $subRequires = $this->getRequires($requiredStmts, $requiredFile);
            $requires = array_merge($requires, $subRequires);

            if ($this->debugMode) {
                print_r($subRequires);
            }
        }

        return $requires;
    }

    /**
     * Get required files from an expression
     *
     * @param object $expr An expression node.
     * @return array List of required files
     */
    public function getExpressionRequires($expr)
    {
        $requires = [];

        if ($expr instanceof \PhpParser\Node\Expr\Include_) {
            $requires[] = $expr->expr;
        } elseif (isset($expr->expr) && $expr->expr instanceof \PhpParser\Node\Expr\Include_) {
            $requires[] = $expr->expr;
        }

        return $requires;
    }

    /**
     * Get a simple list of all dependency file paths
     *
     * @return array List of dependency paths
     */
    public function getDependencies()
    {
        $requires = $this->scan();

        foreach ($requires as $require) {
            $this->dependencies[] = $require['full_path'];
        }

        return $this->dependencies;
    }

    /**
     * Get packages from dependency files
     *
     * @return array List of packages
     */
    public function getPackages()
    {
        foreach ($this->dependencies as $dependency) {
            $filesToCheck = ['composer.json', 'package.json'];

            foreach ($filesToCheck as $file) {
                $packagesFile = dirname($dependency) . '/' . $file;

                if (file_exists($packagesFile)) {
                    $composerData = json_decode(file_get_contents($packagesFile), true);

                    if ($composerData) {
                        $this->packages[] = [
                            'file' => $packagesFile,
                            'data' => $composerData,
                        ];
                    }
                }
            }
        }
        
        return $this->packages;
    }
}