import chalk from 'chalk';
import figlet from 'figlet';

export default function displayBanner() {
  const banner = figlet.textSync('AJ REST API', {
    horizontalLayout: 'full',
  });

  console.log(chalk.cyan(banner));
  console.log(chalk.yellow.bold('🚀 A simple REST API generator'));
  console.log(chalk.gray('────────────────────────────────────────────'));
  console.log(chalk.green('📌 Created by:'), chalk.bold('Aj'));
  console.log(chalk.green('🔗 GitHub:'), chalk.underline.cyan('https://github.com/Aj3322'));
  console.log(chalk.gray('────────────────────────────────────────────\n'));
}
