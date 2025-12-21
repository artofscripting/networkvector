# 🌐 Network Vector

**Advanced Network Topology Scanner with Interactive D3.js Visualization**

Network Vector is a powerful, Python-based network scanning tool that performs comprehensive TCP port discovery without relying on external tools like nmap or masscan. It creates beautiful, interactive D3.js visualizations to map network topology and security posture.

## 🎥 See Network Vector in Action

[![Network Vector Demo](https://img.youtube.com/vi/JDTW9TA8Odg/maxresdefault.jpg)](https://youtu.be/JDTW9TA8Odg)

*Click the image above to watch Network Vector scanning and visualizing enterprise networks*

![Network Vector Banner](https://img.shields.io/badge/Network-Vector-blue?style=for-the-badge&logo=network&logoColor=white)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

### 🚀 Core Capabilities
- **Raw TCP Port Scanning** - Scans 750 unique ports without external dependencies
- **Multi-threaded Performance** - Up to 1000 concurrent threads for fast scanning
- **Deep Scan (Dig)** - Automatically scan all 65535 ports on discovered hosts with `--dig`
- **All Ports Mode** - Scan all 65535 ports on entire network with `--all-ports`
- **Progress Indicator** - Real-time percentage progress shown during scanning
- **Live Mode** - Regenerate graphs in real-time as hosts are discovered with `--live`
- **Randomized Scanning** - Randomizes IP and port scan order for balanced network load
- **Configurable Delays** - Optional random delays between hosts for controlled scanning
- **Host Exemptions** - Exclude specific IPs or CIDRs from scanning with `--exempt`
- **Network Topology Discovery** - Automatic CIDR-based network hierarchy visualization
- **Interactive D3.js Graphs** - Professional force-directed network visualizations
- **SMB Share Enumeration** - Cross-platform Windows/Linux share discovery
- **Hostname Resolution** - Automatic reverse DNS lookup for discovered hosts
- **Comprehensive OS Detection** - Advanced fingerprinting using 100+ port signatures
- **Host Categorization** - Visual host coloring based on detected operating systems

### 🎨 Visualization Features
- **2D Force-Directed Graph** - Interactive D3.js v7 network visualization
- **3D Force-Directed Graph** - Immersive 3D network topology using 3d-force-graph
- **Search & Navigation** - Find nodes by IP, hostname, or port with Previous/Next navigation
- **Glow Highlighting** - Light blue glow effect on search results and selected nodes
- **Click-to-Select** - Click any node to highlight with red label emphasis
- **Double-Click Zoom** - Double-click nodes to center and zoom the view
- **Host Tour Animation** - Play/Pause/Stop animated tour through all discovered hosts (3D)
- **Host Synopsis Panel** - View connected ports and shares when selecting a host
- **Dimming Effect** - Non-matching nodes dim during search for focus
- **Professional Network Icons** - SVG-based network topology representation
- **Host Icons** - PNG icons with embedded base64 encoding for self-contained HTML
- **Text Labels** - Floating labels for hosts and shares in 3D view
- **Color-coded Security** - Risk-based port classification (red=dangerous, blue=safe)
- **Interactive Port Information** - Click ports for detailed descriptions and security assessments
- **Sticky Node Behavior** - Drag-and-drop node positioning with persistence (2D)
- **Camera Controls** - Left-click rotate, right-click pan, scroll to zoom (3D)
- **Node Focus** - Double-click nodes to focus camera view (3D)
- **Collapsible UI Panels** - Hide/show Controls, Info Panel, and Legend to maximize graph space
- **Collapse/Expand** - Right-click network nodes to manage complexity (2D)
- **Self-contained Output** - HTML files with embedded assets, no external dependencies
- **Embedded Scan Data** - Complete scan results embedded in HTML with "Show Scan Data" button
- **CSV Data Export** - Download comprehensive scan data as CSV for analysis in Excel/databases

### 🔍 Port Intelligence
- **Comprehensive Database** - Detailed information for 130+ common services
- **Security Assessment** - Risk levels and vulnerability information for each port
- **Educational Links** - Direct links to service documentation and security resources
- **Service Detection** - Automatic identification of running services
- **Real-time Display** - Interactive port information on double-click

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher (for source code)
- Windows, Linux, or macOS
- **OR use the pre-built executable (no Python required!)**

### Option 1: Pre-built Executable (Recommended)
```bash
# Clone the repository
git clone https://github.com/artofscripting/networkvector.git
cd networkvector

# Download the latest executable from Releases tab on GitHub
# Or build it yourself using the instructions below

# Run immediately with no setup required
./nvector.exe 192.168.1.0/24

# All features included: 1000 threads, embedded data, interactive visualization
```

**Note**: Pre-built executables are available in the [Releases section](https://github.com/artofscripting/networkvector/releases) of this repository.

### Option 2: Python Source

### Quick Start
```bash
# Clone the repository
git clone https://github.com/artofscripting/networkvector.git
cd networkvector

# Install dependencies (none required - uses only Python standard library!)

# Run a basic scan (uses 1000 threads by default for maximum speed)
python src/nvector.py 192.168.1.1

# Scan entire network with full features
python src/nvector.py 192.168.1.0/24 --resolve-hostnames --enumerate-shares

# Use the pre-built executable (no Python required!)
./nvector.exe 192.168.1.0/24
```

### Build Executable (Optional)
```bash
# Install PyInstaller
pip install pyinstaller

# Navigate to source directory
cd src

# Build standalone executable with all dependencies
pyinstaller --onefile --add-data "custom_d3_graph.py;." --hidden-import=webbrowser --name="nvector" nvector.py

# Run the executable
./dist/nvector.exe 192.168.1.0/24
```

**Pre-built Executable Available**: A ready-to-use `nvector.exe` is included in the repository for immediate use without Python installation.

## 📖 Usage Examples

### Basic Network Scan
```bash
# Scan a single host (uses 1000 threads by default)
python src/nvector.py 192.168.1.100

# Or use the pre-built executable
./nvector.exe 192.168.1.100

# Scan a network range
python src/nvector.py 192.168.1.0/24
```

### Advanced Scanning
```bash
# Full feature scan with hostname resolution and SMB enumeration (default 1000 threads)
python src/nvector.py 192.168.1.0/24 --resolve-hostnames --enumerate-shares

# Generate 3D visualization in addition to 2D graph
python src/nvector.py 192.168.1.0/24 --3d

# Scan multiple networks with 3D visualization
python src/nvector.py 192.168.1.0/24,10.0.0.0/24 --3d --timeout 1.5

# Deep scan - discover hosts then scan all 65535 ports on each
python src/nvector.py 192.168.1.0/24 --dig

# Scan all ports on entire network (slow but thorough)
python src/nvector.py 192.168.1.0/24 --all-ports

# Live mode - graphs update in real-time as hosts are found
python src/nvector.py 192.168.1.0/24 --live --3d

# Exempt specific hosts or subnets from scanning
python src/nvector.py 192.168.1.0/24 --exempt 192.168.1.1,192.168.1.254

# Exempt an entire subnet while scanning a larger range
python src/nvector.py 10.0.0.0/16 --exempt 10.0.1.0/24,10.0.2.0/24

# Reduce threads for controlled scanning
python src/nvector.py 192.168.1.0/24 --threads 50

# Add delays between hosts for gentler scanning
python src/nvector.py 192.168.1.0/24 --scan-delay 1.0 --threads 50

# Disable randomization for sequential scanning
python src/nvector.py 192.168.1.0/24 --no-randomize

# Custom port range
python src/nvector.py 192.168.1.1 --ports 22 80 443 3389 5432

# Custom timeout for slow networks
python src/nvector.py 192.168.1.0/24 --timeout 2.0

# Maximum performance with executable
./nvector.exe 192.168.1.0/24 --threads 1000 --no-randomize
```

### Output Options
```bash
# Skip graph generation and export to CSV instead
python src/nvector.py 192.168.1.0/24 --no-graph

# Disable specific features
python src/nvector.py 192.168.1.0/24 --no-resolve-hostnames --no-enumerate-shares
```

## 🎯 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | IP address or network (e.g., 192.168.1.1 or 192.168.1.0/24) | Required |
| `--timeout` | Connection timeout in seconds | 3.0 |
| `--threads` | Maximum number of scanning threads | 1000 |
| `--ports` | Custom ports to scan | 750 common ports |
| `--all-ports` | Scan all 65535 ports (slow) | Disabled |
| `--dig` | Deep scan all 65535 ports on discovered hosts | Disabled |
| `--live` | Live mode: regenerate graphs after each host found | Disabled |
| `--exempt` | Comma-separated IPs or CIDRs to exclude from scanning | None |
| `--no-graph` | Skip D3.js visualization generation and export to CSV | Enabled |
| `--no-resolve-hostnames` | Disable reverse DNS lookup | Enabled |
| `--no-enumerate-shares` | Disable SMB share enumeration | Enabled |
| `--no-randomize` | Disable randomized scanning order | Randomization enabled |
| `--scan-delay` | Max random delay between hosts (seconds) | 0.0 |
| `--3d`, `--force-3d` | Generate additional 3D force-directed graph visualization | Disabled |

## 🎯 3D Visualization

Network Vector now supports immersive 3D network topology visualization using the 3d-force-graph library.

### Enable 3D Mode
```bash
# Generate both 2D and 3D visualizations
python src/nvector.py 192.168.1.0/24 --3d

# Scan multiple networks with 3D output
python src/nvector.py 192.168.1.0/24,10.0.0.0/24 --3d
```

### 3D Features
- **Interactive 3D Navigation**
  - Left-click + drag to rotate the view
  - Right-click + drag to pan
  - Scroll to zoom in/out
  
- **Search & Highlighting**
  - Search for hosts, IPs, or ports using the search box
  - Light blue glow effect on matching nodes
  - Previous/Next navigation through results
  - Non-matching nodes dim for focus
  
- **Node Selection**
  - Click any node to select and view details
  - Selected node shows red, larger label
  - Host synopsis shows connected ports and shares
  
- **Host Tour Animation**
  - Play button starts animated tour through hosts
  - Smooth cinematic camera movement
  - Pause/Stop controls for tour
  - Info panel updates with host synopsis during tour
  
- **Visual Elements**
  - Floating text labels for hosts (white on black background)
  - Floating text labels for shares (pink on dark red background)
  - OS-based host node colors (same as 2D)
  - Risk-based port node colors (red/blue)
  - Yellow link connections
  
- **Output**
  - Generates timestamped 3D HTML file (e.g., `network_scan_20251118_161541_3d.html`)
  - Self-contained with all dependencies embedded
  - Works offline with no external resources needed
  - Same embedded scan data and CSV export features as 2D

### Controls (3D View)
- **Alt+C** - Toggle Controls panel
- **Alt+I** - Toggle Info panel
- **Alt+L** - Toggle Legend
- **Alt+S** - Focus search box
- **Escape** - Clear search
- **Click node** - Select and display node details with host synopsis
- **Double-click node** - Center and zoom to node
- **Left-click + drag** - Rotate view
- **Right-click + drag** - Pan view
- **Scroll** - Zoom in/out
- **Play button** - Start host tour animation
- **Pause button** - Pause host tour
- **Stop button** - Stop host tour and reset

## � Output Format

### Interactive HTML Visualization (Default)
Network Vector generates self-contained HTML files with:

#### 2D Visualization (Always Generated)
- **Force-directed network graph** with D3.js v7
- **Professional network topology** representation with SVG icons
- **Interactive port information** with security details for 130+ ports
- **Collapsible UI controls** - Hide/show panels with keyboard shortcuts (Alt+C, Alt+I, Alt+L)
- **CSV data export** - Download complete scan data for spreadsheet analysis
- **Embedded scan data** - complete analysis data built into the HTML file
- **Show Scan Data button** - view raw scan results without separate JSON files
- **Responsive design** for desktop and mobile viewing
- **Timestamped filename** for historical tracking (e.g., `network_scan_20251118_161541.html`)
- **No external dependencies** - works offline with all assets embedded

#### 3D Visualization (--3d flag)
- **Immersive 3D force-directed graph** using 3d-force-graph library
- **Interactive camera controls** - Rotate, pan, zoom, and focus
- **Floating text labels** - Host and share names visible in 3D space
- **Same data and features** as 2D view with spatial depth
- **Separate timestamped file** (e.g., `network_scan_20251118_161541_3d.html`)
- **Fully self-contained** - no external libraries or resources needed

### Automatic CSV Export (--no-graph)
When using `--no-graph`, Network Vector automatically exports results to CSV:
- **Automatic Generation** - CSV file created immediately after scan completion
- **Comprehensive Data** - All scan results, host details, and metadata included
- **Timestamped Files** - Format: `network_scan_YYYYMMDD_HHMMSS.csv`
- **Ready for Analysis** - Compatible with Excel, Google Sheets, databases
- **No Manual Export** - Eliminates need for manual CSV download from HTML

### Key Features:
- **Drag-and-drop nodes** with sticky positioning
- **Right-click collapse/expand** for network organization
- **Double-click port details** with security assessments
- **Color-coded risk levels** (red for dangerous, blue for safe ports)
- **Network hierarchy visualization** with CIDR-based topology
- **CSV data export** - Complete scan data export with:
  - Separate rows for ports and SMB shares (no mixing)
  - Host details (IP, hostname, response times)
  - Port information (port number, service name) in dedicated rows
  - SMB shares in their own dedicated rows
  - OS detection results
  - Scan metadata and configuration
  - Timestamped filenames for historical analysis

## 🔧 Technical Details

### Architecture
- **Pure Python Implementation** - No external scanning tools required
- **Socket-based Scanning** - Raw TCP connection attempts
- **Multi-threaded Design** - Concurrent scanning for performance
- **Modular Structure** - Separate scanning and visualization components

### Port Coverage
Network Vector scans **998 unique ports** covering:
- **System Services** (1-1024): SSH, HTTP, HTTPS, FTP, Telnet, etc.
- **Database Ports** (1433, 3306, 5432, etc.): SQL Server, MySQL, PostgreSQL
- **Application Services** (8080, 9000, etc.): Web applications and APIs
- **Development Ports** (3000-4000): Node.js, Rails, Django applications
- **Enterprise Services** (389, 636, etc.): LDAP, Active Directory

### Visualization Technology
- **D3.js v7** - Latest version for maximum compatibility
- **Force-directed Layout** - Automatic node positioning with physics simulation
- **SVG Rendering** - Scalable vector graphics for crisp visuals
- **Base64 Embedding** - Self-contained HTML with no external dependencies

## 🛡️ Security Considerations

### Ethical Use
- **Educational Purpose** - Designed for learning network security concepts
- **Authorized Testing Only** - Only scan networks you own or have permission to test
- **Responsible Disclosure** - Report vulnerabilities through proper channels

### Responsible Scanning
Network Vector performs TCP scanning which generates network traffic. For responsible scanning:
- Use `--exempt` to exclude sensitive hosts
- Use appropriate thread counts for your network
- Use `--scan-delay` to reduce scanning speed when needed
- Always obtain proper authorization before scanning

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to the branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/networkvector.git
cd networkvector

# Create development branch
git checkout -b feature/your-feature

# Make changes and test
python src/nvector.py 127.0.0.1 --threads 10
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **D3.js Community** - For the incredible visualization framework
- **Python Community** - For the robust standard library that makes this possible
- **Network Security Community** - For inspiration and best practices
- **Open Source Contributors** - For making tools like this possible

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/artofscripting/networkvector/issues)
- **Discussions**: [GitHub Discussions](https://github.com/artofscripting/networkvector/discussions)
- **Documentation**: [Project Wiki](https://github.com/artofscripting/networkvector/wiki)

---

**Network Vector** - Mapping networks, visualizing security, empowering defenders.

*Made with ❤️ by the ArtOfScripting community*