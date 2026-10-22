# PHP2Shell Discovery Tools

Public tooling from Defendable for discovering PHP instances across your infrastructure.

## Tools

### PowerShell: `index.php` discovery

Checks `/index.php` across common web server ports. Endpoints returning HTTP `200` are written to a CSV file together with the page title.

**Important:** A `200` response does not confirm that PHP is installed or executing. Treat matches as leads for further investigation. No matches do not rule out the presence of PHP.

Additional detection methods, including tooling for identifying potentially vulnerable PHP versions, will be added as they are developed and tested.

> **Only scan systems and networks you are authorized to test.**
