import fs from 'fs-extra';
import path from 'path';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// Support __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Templates
// If your templates use default exports
// import templates from './templates/index.js';
import { commonJsFolders, commonJsFiles } from '../templates/commonjs/index.js';
import { esmFolders, esmFiles } from '../templates/module/index.js';

/**
 * Create a REST API project
 * @param {string} projectPath - Path to create the project
 * @param {string} projectName - Name of the project
 * @param {string} moduleType - 'commonjs' or 'module'
 */
export async function createRestApi(projectPath, projectName, moduleType = 'commonjs') {
  console.log(chalk.blue(`\nCreating ${projectName} REST API with ${moduleType.toUpperCase()}...\n`));

  try {
    // Validate project name
    if (!/^[a-z0-9-]+$/.test(projectName)) {
      throw new Error('Project name should only contain lowercase letters, numbers, and hyphens');
    }

    // Check if directory exists
    if (fs.existsSync(projectPath)) {
      const { overwrite } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'overwrite',
          message: `Directory ${projectName} already exists. Overwrite?`,
          default: false
        }
      ]);
      
      if (!overwrite) {
        console.log(chalk.yellow('Operation cancelled.'));
        process.exit(0);
      }
      
      // Remove existing directory
      fs.removeSync(projectPath);
    }

    // Create project directory
    fs.mkdirSync(projectPath, { recursive: true });

    // Select appropriate template based on module type
    const folders = moduleType === 'module' ? esmFolders : commonJsFolders;
    const files = moduleType === 'module' ? esmFiles : commonJsFiles;

    // Create folder structure
    folders.forEach((folder) => {
      const dir = path.join(projectPath, folder);
      fs.mkdirSync(dir, { recursive: true });
      console.log(chalk.green(`📁 Created folder: ${folder}`));

      if (!['logs', 'uploads', 'public', 'docs'].includes(folder)) {
        const ext = moduleType === 'module' ? 'js' : 'js';
        const indexPath = path.join(dir, `index.${ext}`);
        
        const content = moduleType === 'module' 
          ? `// ${folder} module exports\nexport default {};\n`
          : `// ${folder} module exports\nmodule.exports = {};\n`;
        
        fs.writeFileSync(indexPath, content);
        console.log(chalk.green(`📄 Created file: ${folder}/index.${ext}`));
      }
    });

    // Create files
    for (const [filePath, content] of Object.entries(files)) {
      const fullPath = path.join(projectPath, filePath);
      const dir = path.dirname(fullPath);

      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      let fileContent = content
        .replace(/{{projectName}}/g, projectName)
        .replace(/{{moduleType}}/g, moduleType);

      const finalPath = moduleType === 'module' && filePath.endsWith('.js') 
        ? fullPath
        : fullPath;

      fs.writeFileSync(finalPath, fileContent);
      console.log(chalk.green(`📄 Created file: ${path.relative(projectPath, finalPath)}`));
    }

    // Post-create instructions
    // Post-create instructions
    console.log(chalk.bold.green('\n✅ Project created successfully!'));
    console.log(chalk.yellow('👉 Run the following commands to get started:'));
    console.log(chalk.cyan(`   cd ${projectName}`));
    console.log(chalk.cyan('   npm install'));
    console.log(chalk.cyan('   npx npm-check-updates -u --dep dev && npm install'));
    console.log(chalk.cyan('   npm run dev'));


  } catch (error) {
    console.error(chalk.red('\n❌ Error creating project:'), error.message);
    process.exit(1);
  }
}
