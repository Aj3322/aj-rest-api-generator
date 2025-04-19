# AJ REST API Generator 🚀

[![npm version](https://img.shields.io/npm/v/aj-rest-api-generator)](https://npmjs.com/package/aj-rest-api-generator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js CI](https://github.com/yourusername/aj-rest-api-generator/actions/workflows/test.yml/badge.svg)](https://github.com/Aj3322/aj-rest-api-generator/actions/workflows/test.yml)

A CLI tool to instantly scaffold production-ready Node.js REST APIs with either CommonJS or ES Modules support.

![CLI Demo](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExcDl6cGZqY3BmZ2Z6d2V1ZGN4bWJ6NnRjcHZ2eGJtZzB1eHZ6bGZ1biZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/xT5LMHxhOfscxPfIfm/giphy.gif)

## Features ✨

- ⚡️ Instant REST API scaffolding
- 🔄 Supports both CommonJS and ES Modules
- 📁 Organized folder structure
- 🔐 Built-in best practices
- 🛠️ Configurable options
- 📦 Ready-to-use with Express.js

## Installation 📦

### Global Installation (Recommended)
```bash
npm install -g aj-rest-api-generator
```

### Local Installation
```bash
npm install aj-rest-api-generator --save-dev
```

## Usage 🚀

### Interactive Mode
```bash
aj create
```

### With ES Modules
```bash
aj create rest --name my-api --module
```

### With CommonJS (default)
```bash
aj create rest --name my-api --commonjs
```

## Options ⚙️

| Option                | Description                                      | Default     |
|-----------------------|--------------------------------------------------|-------------|
| `-n, --name <name>`   | Set project name                                 | `rest-api`  |
| `--module`            | Use ES Modules format                            | `false`     |
| `--commonjs`          | Use CommonJS format (default)                    | `true`      |
| `-f, --force`         | Overwrite existing directory without prompting   | `false`     |
| `-y, --yes`           | Skip all prompts using default values            | `false`     |
| `-v, --version`       | Show package version                             | -           |
| `-h, --help`          | Display help information                         | -           |

### Behavior Notes:
- When neither `--module` nor `--commonjs` is specified:
  - In interactive mode: Prompts for selection
  - With `--yes`: Defaults to CommonJS
- `--force` will delete existing directories without confirmation
- `--yes` will use these defaults:
  - Project name: `rest-api`
  - Module system: CommonJS
  - No directory overwriting (unless combined with `--force`)

## Project Structure 📂

Generated projects include:

```
project-root/
|──  src/
|     ├── config/               # Configuration files
|     ├── controllers/          # Route controllers
|     ├── models/               # Database models
|     ├── routes/               # Route definitions
|     ├── middlewares/          # Custom express middlewares
|     ├── services/             # Business logic services
|     ├── utils/                # Utility classes and functions
|     ├── validations/          # Request validation schemas
|     └── constants/            # Constants definitions
|──  tests/               # Test files
|──  docs/                # API documentation files
|──  logs/                # Log files
|──  public/              # Public assets
|──  uploads/             # File uploads
|──  .env.example         # Example environment variables
├──  .env                 # Environment variables
├──  .gitignore           # Git ignore file
├──  .eslintrc.js         # ESLint configuration
└──  .prettierrc          # Prettier configuration
```

## Development 🛠️

1. Clone the repo:
```bash
git clone https://github.com/yourusername/aj-rest-api-generator.git
```

2. Install dependencies:
```bash
npm install
```

3. Link for local development:
```bash
npm link
```

4. Test your changes:
```bash
npm test
```

## Contributing 🤝

Contributions are welcome! Please follow these steps:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support 💖

If you find this project useful, please consider starring ⭐ the repository or buying me a coffee ☕:

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/yourusername)
```