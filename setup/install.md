# \# Setup

# 

# How the lab environment was built. Tested with Splunk Enterprise 10.6.2.5 on Windows.

# 

# \## 1. Install Splunk Enterprise

# 

# Download the Windows installer from the Splunk website and install it with the default options. Open Splunk Web at `http://localhost:8000`.

# 

# \## 2. Download the dataset

# 

# Get the pre-indexed BOTS v3 archive (about 320 MB) from the official repository: https://github.com/splunk/botsv3

# 

# Check the MD5 hash against the value on that page:

# 

# ```powershell

# Get-FileHash .\\botsv3\_data\_set.tgz -Algorithm MD5

# ```

# 

# \## 3. Extract into the Splunk apps folder

# 

# Use 7-Zip. Open `botsv3\_data\_set.tgz`; if you see a `.tar` inside, open that too. Copy the whole `botsv3\_data\_set` folder to:

# 

