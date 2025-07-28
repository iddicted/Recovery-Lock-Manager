![Recover Lock Enabler](./Images/recovery-lock-enabler.png)

# Recovery-Lock-Enabler
---


This script enables the recovery lock on a device, which is useful for preventing unauthorized access to the recovery mode.

It uses the Jamf Pro API to create a Smart Group that identifies computers where Recovery Lock is not enabled, retrieves the members of this group, and sets the Recovery Lock for each computer.

## Requirements
- Access to the Jamf Pro API
- Jamf Pro API credentials (client ID and client secret)
- Desired Group Name
- jq (JSON processor)
- bash (or compatible shell)

## Require Permissions for API Client
- Read Advanced Computer Searches
- Send Set Recovery Lock Command
- Read Smart Computer Groups
- View MDM command information in Jamf Pro API
- Read Computers, Create Smart Computer Groups

## Usage
1. Clone the repository or download the script.
2. Open the script in a text editor.
3. Update the variables at the top of the script with your Jamf Pro API credentials and the desired group name.
   1. (If you are using sites in Jamf Pro, ensure to set the `site_ID` variable to the appropriate site ID or leave it as `-1` for all sites.)
4. Save the script.
5. Run the script in your terminal. 
    ```shell
    sh recovery-lock-enabler.sh
    ```

## Variables
- jamf_pro_url: The URL of your Jamf Pro server.
- client_id: The client ID for your Jamf Pro API.
- client_secret: The client secret for your Jamf Pro API.
- group_name: The name of the Smart Group to be created.
- site_ID: The site ID for the Smart Group (default is `-1` for all sites).