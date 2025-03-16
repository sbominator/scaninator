# Scanninator

A PHP dependency scanner that analyzes PHP files to extract and resolve all include/require statements. This tool can scan both local files and PHP files from GitHub repositories.

## Requirements

- PHP 7.0 or later
- Composer
- Git (for GitHub repository scanning)
- PHP Tokenizer extension

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/sbominator/scanninator.git
   cd scanninator
   ```

2. Install dependencies with Composer:
   ```bash
   composer install
   ```

## Usage

### Command Line Interface

The simplest way to use Scanninator is through the command line:

```bash
php cli.php <filename or GitHub URL>
```

#### Examples:

Scan a local file:
```bash
php cli.php path/to/file.php
```

Scan a file from a GitHub repository:
```bash
php cli.php https://github.com/owner/repo/blob/main/path/to/file.php
```

### Programmatic Usage

You can also use Scanninator in your own PHP scripts:

```php
<?php
require 'vendor/autoload.php';

$scanner = new \Scanninator\Scanninator('path/to/file.php');
$dependencies = $scanner->get_dependencies();

print_r($dependencies);
```

## Features

- Scans PHP files for `require`, `require_once`, `include`, and `include_once` statements
- Resolves paths of dependencies (handles relative paths, `__DIR__`, etc.)
- Recursively analyzes dependencies to build a complete dependency tree
- Support for scanning files directly from GitHub repositories

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.