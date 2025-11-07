# CSV Export Format Example

When you click "📊 Download CSV" in Network Vector, you'll get a file with this structure:

## CSV Header
```csv
Type,IP Address,Hostname,Port,Service,SMB Share,OS Detection,Response Time
```

## Sample Output (separate rows for ports and shares)
```csv
Port,192.168.1.10,webserver.local,80,http,,Linux (Medium confidence),0.045ms
Port,192.168.1.10,webserver.local,443,https,,Linux (Medium confidence),0.043ms
Port,192.168.1.10,webserver.local,22,ssh,,Linux (Medium confidence),0.032ms
Share,192.168.1.10,webserver.local,,,ADMIN$,Linux (Medium confidence),0.040ms
Share,192.168.1.10,webserver.local,,,C$,Linux (Medium confidence),0.040ms
Port,192.168.1.20,database.local,3306,mysql,,Linux (High confidence),0.032ms
Port,192.168.1.20,database.local,1433,ms-sql-s,,Linux (High confidence),0.028ms
Port,192.168.1.30,fileserver.local,445,microsoft-ds,,Windows (High confidence),0.021ms
Port,192.168.1.30,fileserver.local,139,netbios-ssn,,Windows (High confidence),0.019ms
Share,192.168.1.30,fileserver.local,,,ADMIN$,Windows (High confidence),0.020ms
Share,192.168.1.30,fileserver.local,,,SharedDocs,Windows (High confidence),0.020ms
Share,192.168.1.30,fileserver.local,,,Backups,Windows (High confidence),0.020ms
```

## Row Structure
- **Type column**: Clearly identifies whether the row represents a "Port" or "Share"
- **Port rows**: Type="Port", have Port and Service columns filled, SMB Share column empty
- **Share rows**: Type="Share", have SMB Share column filled, Port and Service columns empty
- **OS Detection**: Real OS fingerprinting results with confidence levels (High/Medium/Low)
- **Response Time**: Actual connection timing data in milliseconds per port/share

## Benefits for Analysis
- **Clear categorization**: Type column makes it easy to filter ports vs shares instantly
- **Excel-friendly**: Each port and share gets its own dedicated row with clear labeling
- **Clean separation**: Ports and shares don't mix - easier to filter and analyze
- **Database import**: Perfect structure for SQL analysis with separate port/share tables
- **Pivot tables**: Create summaries by Type, IP, service, or share independently
- **Advanced filtering**: Filter by Type="Port" for network services or Type="Share" for file resources
- **Performance analysis**: Real response times enable latency analysis and network optimization
- **Security assessment**: OS detection data helps identify vulnerable systems and patch levels

## Scan Metadata
The CSV also includes metadata at the bottom:
```csv
# Scan Metadata
# Target: 192.168.1.0/24
# Scan Time: 2025-11-07 10:15:00
# Total Hosts: 15
# Ports Scanned: 998 ports
# Hostname Resolution: Enabled
# Share Enumeration: Enabled
```