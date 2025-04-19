#!/usr/bin/env node

import { program } from 'commander';
import path from 'path';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

import { createRestApi } from '../lib/creator.mjs'; // Update path if needed
import displayBanner from '../lib/utils.mjs'; // Assuming utils exports default

// Support __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Display banner
displayBanner();

program
  .name('aj')
  .description('CLI tool for generating REST API boilerplate')
  .version('1.0.5', '-v, --version', 'Show version');

program
  .command('create')
  .description('Create a new REST API project')
  .argument('[type]', 'Project type (rest|api)', 'rest')
  .option('-n, --name <name>', 'Project name')
  .option('--commonjs', 'Use CommonJS modules')
  .option('--module', 'Use ES Modules')
  .option('-f, --force', 'Overwrite existing directory')
  .action(async (type, options) => {
    try {
      if (!['rest', 'api'].includes(type)) {
        throw new Error('Invalid project type. Available types: rest, api');
      }

      let projectName = options.name;
      if (!projectName) {
        const answer = await inquirer.prompt([
          {
            type: 'input',
            name: 'projectName',
            message: 'Enter project name:',
            default: 'rest-api',
            validate: input => input.trim() ? true : 'Project name cannot be empty'
          }
        ]);
        projectName = answer.projectName;
      }

      let moduleType = 'commonjs';
      if (options.module) {
        moduleType = 'module';
      } else if (!options.commonjs && !options.module) {
        const answer = await inquirer.prompt([
          {
            type: 'list',
            name: 'moduleType',
            message: 'Select module system:',
            choices: [
              { name: 'CommonJS', value: 'commonjs' },
              { name: 'ES Modules', value: 'module' }
            ],
            default: 'commonjs'
          }
        ]);
        moduleType = answer.moduleType;
      }

      const projectPath = path.join(process.cwd(), projectName);

      await createRestApi(projectPath, projectName, moduleType, {
        force: options.force
      });

    } catch (error) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(1);
    }
  });

program.helpCommand('help [command]', 'Show help for a specific command');

program.on('--help', () => {
  console.log('\nExamples:');
  console.log(`  ${chalk.cyan('$ aj create rest --name my-api --module')}`);
  console.log(`  ${chalk.cyan('$ aj create api --commonjs')}`);
  console.log(`  ${chalk.cyan('$ aj create')} ${chalk.gray('(interactive mode)')}`);
});

program.parse(process.argv);

if (process.argv.length < 3) {
  program.help();
}
