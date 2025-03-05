# BetterDiscordPlugins
Better Discord Plugins That Barely Work


# VirusTotalScanner for BetterDiscord

A powerful BetterDiscord plugin that scans links in Discord messages using the VirusTotal API to identify potential security threats.

![Screenshot of VirusTotalScanner in action](https://i.imgur.com/IMAGEID.png)



## Features

- **Link Scanning**: Automatically adds scan buttons to links in Discord messages
- **Visual Indicators**: Color-codes links based on scan results (malicious, suspicious, or clean)
- **Detailed Tooltips**: Shows comprehensive scan results including detection engines
- **Collection Management**: Create and manage collections of threats for later reference
- **File Graph Support**: Visualize relationships between malicious files and URLs
- **Local Storage**: Maintains collections and graphs locally for non-enterprise users
- **Auto-Tracking**: Option to automatically add discovered threats to collections/graphs
- **Rate Limiting**: Respects VirusTotal API limits to ensure reliable scanning

## Installation

1. Make sure [BetterDiscord](https://betterdiscord.app/) is installed
2. Download the `VirusTotalScanner.plugin.js` file
3. Place it in your BetterDiscord plugins folder:
   - Windows: `%AppData%\BetterDiscord\plugins\`
   - Mac: `~/Library/Application Support/BetterDiscord/plugins/`
   - Linux: `~/.config/BetterDiscord/plugins/`
4. Enable the plugin in BetterDiscord settings
5. Add your VirusTotal API key in the plugin settings

## Getting a VirusTotal API Key

To use this plugin, you'll need a VirusTotal API key:

1. Create a free account at [VirusTotal](https://www.virustotal.com)
2. After logging in, go to your profile settings
3. Access the API key section to get your personal API key
4. Copy this key and paste it into the plugin settings

**Note**: The free VirusTotal API has a limit of 4 requests per minute. For higher limits, consider a premium VirusTotal account.

## Usage

### Basic Link Scanning

1. When you see a link in Discord, a "Scan" button will appear next to it
2. Click the button to scan the link with VirusTotal
3. The link will change color based on the result:
   - 🔴 Red: Malicious
   - 🟠 Orange: Suspicious
   - 🟢 Green: Clean
4. Hover over a scanned link to see detailed results

### Collections and Graphs

#### Creating Collections
1. Go to plugin settings
2. Under "VirusTotal Collections," click "Add New Collection"
3. Enter a name for your collection
4. Click "Create"

#### Adding Links to Collections
- Hover over a scanned link
- Select a collection from the dropdown in the tooltip
- The link will be added to that collection

#### Viewing Collections
1. Go to plugin settings
2. Find your collection in the list
3. Click "View" to see all items

#### Creating and Using Graphs
Similar to collections, you can create graphs to visualize relationships between malicious URLs and files.

### Auto-Tracking

Enable automatic tracking in the settings to have the plugin automatically add malicious or suspicious links to your designated collections and graphs.

## Privacy and Security

- Your VirusTotal API key is stored locally on your device
- Links are only sent to VirusTotal for scanning
- No data is shared with any other third parties
- Collections and graphs can be stored locally without requiring a premium VirusTotal account

## Limitations

- Free VirusTotal API accounts are limited to 4 requests per minute
- Some VirusTotal features (remote collections/graphs) require an enterprise account
- The plugin does not scan downloaded files, only links

## License

[MIT License](LICENSE)

## Credits

- [VirusTotal](https://www.virustotal.com) for their excellent security API
- [BetterDiscord](https://betterdiscord.app/) for the plugin platform

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
