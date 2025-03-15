<?php

use PhpParser\ParserFactory;

require 'vendor/autoload.php';

/**
 * PHP Dependency Scanner
 *
 * This class scans PHP files for dependencies (require/include statements)
 * and resolves their full paths. It can scan local files or download and scan
 * files from GitHub repositories.
 */
class PHP_Dependency_Scanner {

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
	private $tmp_dir;

	/**
	 * Flag to indicate if we're working with a GitHub URL
	 *
	 * @var boolean
	 */
	private $is_github_url = false;

	/**
	 * Constructor
	 *
	 * @param string $input The PHP file to analyze or a GitHub URL.
	 */
	public function __construct( $input ) {
		$this->check_dependencies();

		$this->parser = ( new ParserFactory() )->createForNewestSupportedVersion();

		if ( $this->is_github_url( $input ) ) {
			$this->is_github_url = true;
			$this->filename      = $this->setup_github_repo( $input );
		} else {
			$this->filename = $input;
		}
	}

	private function check_dependencies() {
		$required_extensions = array( 'tokenizer' );

		foreach ( $required_extensions as $ext ) {
			if ( ! extension_loaded( $ext ) ) {
				echo "The {$ext} extension is required for this script to run.\n";
				exit( 1 );
			}
		}

		$commands = array( 'git' );

		foreach ( $commands as $command ) {
			if ( ! shell_exec( 'command -v ' . $command ) ) {
				echo "The {$command} command is required for this script to run.\n";
				exit( 1 );
			}
		}
	}

	/**
	 * Check if the input is a GitHub URL
	 *
	 * @param string $url The URL to check.
	 * @return boolean True if the URL is a GitHub URL.
	 */
	private function is_github_url( $url ) {
		return preg_match( '/^https?:\/\/github\.com\//', $url ) === 1;
	}

	/**
	 * Setup a GitHub repository for scanning
	 *
	 * @param string $github_url The GitHub URL.
	 * @return string The path to the file to scan.
	 */
	private function setup_github_repo( $github_url ) {
		// Create tmp directory if it doesn't exist.
		$base_tmp_dir = __DIR__ . '/tmp';
		if ( ! file_exists( $base_tmp_dir ) ) {
			mkdir( $base_tmp_dir, 0755, true );
		}

		// Parse GitHub URL.
		$url_parts  = parse_url( $github_url );
		$path_parts = explode( '/', trim( $url_parts['path'], '/' ) );

		// Extract repo owner and name.
		$owner = $path_parts[0];
		$repo  = $path_parts[1];

		// Create a unique temp directory for this repo.
		$repo_dir = $base_tmp_dir . '/' . $owner . '_' . $repo . '_' . time();
		mkdir( $repo_dir, 0755, true );
		$this->tmp_dir = $repo_dir;

		// Clone the repository.
		$clone_url        = 'https://github.com/' . escapeshellarg( trim( $owner ) ) . '/' . escapeshellarg( trim( $repo ) ) . '.git';
		$escaped_repo_dir = escapeshellarg( $repo_dir );
		exec( "git clone {$clone_url} {$escaped_repo_dir}" );

		// Determine file path within repo.
		$file_path = '';
		if ( count( $path_parts ) > 4 && $path_parts[2] === 'blob' ) {
			// Format: github.com/owner/repo/blob/branch/path/to/file.php.
			$branch    = $path_parts[3];
			$file_path = $repo_dir . '/' . implode( '/', array_slice( $path_parts, 4 ) );
		} else {
			echo "Invalid GitHub URL format. Expected: https://github.com/owner/repo/blob/branch/path/to/file.php\n";
			exit( 1 );
		}

		// Check if file exists
		if ( ! file_exists( $file_path ) ) {
			echo "File not found in repository: {$file_path}\n";
			exit( 1 );
		}

		return $file_path;
	}

	/**
	 * Cleanup temporary files when done
	 */
	public function cleanup() {
		if ( $this->is_github_url && $this->tmp_dir && file_exists( $this->tmp_dir ) ) {
			$this->delete_directory( $this->tmp_dir );
		}
	}

	/**
	 * Recursively delete a directory
	 *
	 * @param string $dir Directory path to delete
	 * @return bool True on success, false on failure
	 */
	private function delete_directory( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return false;
		}

		$files = array_diff( scandir( $dir ), array( '.', '..' ) );

		foreach ( $files as $file ) {
			$path = $dir . '/' . $file;

			if ( is_dir( $path ) ) {
				$this->delete_directory( $path );
			} else {
				unlink( $path );
			}
		}

		return rmdir( $dir );
	}

	/**
	 * Run the dependency scan
	 *
	 * @return array The list of dependencies
	 */
	public function scan() {
		$stmts = $this->parser->parse( file_get_contents( $this->filename ) );
		return $this->get_requires( $stmts, $this->filename );
	}

	/**
	 * Get all required files from the statements
	 *
	 * @param array  $stmts     The parsed PHP statements.
	 * @param string $main_file The file containing the statements.
	 * @return array List of required files with full paths
	 */
	public function get_requires( $stmts, $main_file ) {
		$requires = array();
		$base_dir = dirname( $main_file );

		foreach ( $stmts as $stmt ) {
			// Handle namespaced code
			if ( $stmt instanceof PhpParser\Node\Stmt\Namespace_ && ! empty( $stmt->stmts ) ) {
				// Recursively scan statements within the namespace
				$namespace_requires = $this->get_requires( $stmt->stmts, $main_file );
				$requires = array_merge( $requires, $namespace_requires );
				continue;
			}

			$expr = null;

			if ( $stmt instanceof PhpParser\Node\Expr\Include_ ) {
				$expr = $stmt->expr;
			} elseif ( $stmt instanceof PhpParser\Node\Stmt\Expression ) {
				if ( $stmt->expr instanceof PhpParser\Node\Expr\Include_ ) {
					$expr = $stmt->expr->expr;
				}
			}

			if ( ! empty( $expr ) ) {
				$required_file = '';

				// Handle concatenation with __DIR__ and other constants.
				if ( $expr instanceof PhpParser\Node\Expr\BinaryOp\Concat ) {
					$left_part  = $expr->left;
					$right_part = $expr->right;

					// Handle __DIR__ . '/something/file.php'.
					if ( $left_part instanceof PhpParser\Node\Scalar\MagicConst\Dir ) {
						if ( $right_part instanceof PhpParser\Node\Scalar\String_ ) {
							// Use dirname() directly instead of concatenating paths that may already contain the repo path.
							$required_file = dirname( $main_file ) . $right_part->value;
						}
					} else { // Handle other cases.
						// Try to extract a path if possible
						if ( $right_part instanceof PhpParser\Node\Scalar\String_ ) {
							$right_value = $right_part->value;

							if ( isset( $expr->left->value ) ) {
								$required_file = $expr->left->value . $right_value;
							} else {
								$required_file = $right_value;
							}
						}
					}
				} elseif ( $expr instanceof PhpParser\Node\Scalar\String_ ) {
					$required_file = $expr->value;
				} else {
					$required_file = $expr->getAttribute( 'rawValue', '' );

					// Clean up quotes if present.
					$required_file = str_replace( "'", '', $required_file );
					$required_file = str_replace( '"', '', $required_file );
				}

				if ( empty( $required_file ) ) {
					continue;
				}

				echo 'Found require: ' . $required_file . PHP_EOL;

				// Determine the full path.
				$full_path = '';
				if ( strpos( $required_file, '/' ) === 0 ) {
					// Absolute path.
					$full_path = $required_file;
				} elseif ( strpos( $required_file, $this->tmp_dir ) === 0 ) {
					// Already contains the full repo path.
					$full_path = $required_file;
				} else {
					// Relative path.
					$full_path = $base_dir . '/' . $required_file;
				}

				// Resolve path (handles .. and . in paths).
				$resolved_path = realpath( $full_path );

				$requires[] = array(
					'original'  => $required_file,
					'full_path' => $resolved_path ? $resolved_path : $full_path,
				);
			}
		}

		// Track processed files to avoid infinite recursion.
		static $processed_files = array();

		foreach ( $requires as $require ) {
			$required_file = $require['full_path'];

			// Skip if already processed.
			if ( in_array( $required_file, $processed_files, true ) ) {
				continue;
			}

			$processed_files[] = $required_file;

			if ( ! file_exists( $required_file ) || is_dir( $required_file ) ) {
				echo 'File does not exist: ' . $required_file . PHP_EOL;
				continue;
			}

			$required_stmts = $this->parser->parse( file_get_contents( $required_file ) );

			echo 'Scanning: ' . $required_file . PHP_EOL;

			$sub_requires = $this->get_requires( $required_stmts, $required_file );
			$requires     = array_merge( $requires, $sub_requires );

			print_r( $sub_requires );
		}

		return $requires;
	}

	/**
	 * Get required files from an expression
	 *
	 * @param object $expr An expression node.
	 * @return array List of required files
	 */
	public function get_expression_requires( $expr ) {
		$requires = array();

		if ( $expr instanceof PhpParser\Node\Expr\Include_ ) {
			$requires[] = $expr->expr;
		} elseif ( $expr->expr instanceof PhpParser\Node\Expr\Include_ ) {
			$requires[] = $expr->expr;
		}

		return $requires;
	}

	/**
	 * Get a simple list of all dependency file paths
	 *
	 * @return array List of dependency paths
	 */
	public function get_dependency_paths() {
		$requires = $this->scan();
		return array_column( $requires, 'full_path' );
	}
}

// Execute the script if run from the command line.
if ( php_sapi_name() === 'cli' ) {
	if ( isset( $argv[1] ) ) {
		$scanner      = new PHP_Dependency_Scanner( $argv[1] );
		$dependencies = $scanner->scan();

		echo 'Requires: ' . PHP_EOL;
		print_r( array_column( $dependencies, 'full_path' ) );

		// Cleanup temp files if needed.
		// $scanner->cleanup();
	} else {
		echo 'Usage: php sca.php <filename or GitHub URL>' . PHP_EOL;
		echo 'Example GitHub URL: https://github.com/owner/repo/blob/main/path/to/file.php' . PHP_EOL;
	}
}
