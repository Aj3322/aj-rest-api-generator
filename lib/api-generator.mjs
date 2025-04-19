const fs = require('fs-extra');
const path = require('path');
const chalk = require('chalk');

// Templates
const { folders, files } = require('./templates');

/**
 * Create a REST API project
 * @param {string} projectPath - Path to create the project
 * @param {string} projectName - Name of the project
 */
function createRestApi(projectPath, projectName) {
  console.log(chalk.blue(`Creating REST API project at ${projectPath}\n`));

  try {
    // Create project directory if it doesn't exist
    if (!fs.existsSync(projectPath)) {
      fs.mkdirSync(projectPath, { recursive: true });
    }

    // Create folders
    folders.forEach((folder) => {
      const dir = path.join(projectPath, folder);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(chalk.green(`📁 Created folder: ${folder}`));

        // Add index.js to each folder
        if (!['logs', 'uploads', 'public', 'docs'].includes(folder)) {
          const indexPath = path.join(dir, 'index.js');
          if (!fs.existsSync(indexPath)) {
            fs.writeFileSync(indexPath, `// ${folder} module exports\nmodule.exports = {};\n`);
            console.log(chalk.green(`📄 Created file: ${folder}/index.js`));
          }
        }
      }
    });

    // Create files
    for (const [filePath, content] of Object.entries(files)) {
      const fullPath = path.join(projectPath, filePath);
      const dir = path.dirname(fullPath);

      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      // If this is package.json, replace project name
      let fileContent = content;
      if (filePath === 'package.json') {
        fileContent = content.replace('"name": "rest-api"', `"name": "${projectName}"`);
      }
      
      fs.writeFileSync(fullPath, fileContent);
      console.log(chalk.green(`📄 Created file: ${filePath}`));
    }

    console.log(chalk.bold.green('\n✅ Project structure created successfully.'));
    console.log(chalk.yellow('👉 Run the following commands to get started:'));
    console.log(chalk.cyan(`   cd ${projectName}`));
    console.log(chalk.cyan('   npm install'));
    console.log(chalk.cyan('   npm run dev'));

  } catch (error) {
    console.error(chalk.red('Error creating project:'), error);
    process.exit(1);
  }
}

module.exports = {
  createRestApi
};