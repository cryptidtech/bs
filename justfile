# Build Script 
build:
  # Calls the just command in crates/comrade-component (just build): 
  just crates/comrade-component/build

test:
  cargo test --all --workspace 
  just crates/bs-peer/test-web
  just crates/multikey/test-wasm

check32:
  just crates/bs-peer/check32

# Update ChromeDriver to match the installed Chrome/Chromium version
update-chromedriver:
    #!/usr/bin/env bash
    set -euo pipefail

    # Function to get the major version
    get_major_version() {
        echo "$1" | cut -d '.' -f1
    }

    # Find the installed Chrome/Chromium version
    if command -v google-chrome &> /dev/null; then
        CHROME_VERSION=$(google-chrome --version | awk '{print $3}')
        echo "Using Google Chrome"
    elif command -v google-chrome-stable &> /dev/null; then
        CHROME_VERSION=$(google-chrome-stable --version | awk '{print $3}')
        echo "Using Google Chrome"
    elif command -v chromium &> /dev/null; then
        CHROME_VERSION=$(chromium --version | awk '{print $2}')
        echo "Using Chromium"
    elif command -v chromium-browser &> /dev/null; then
        CHROME_VERSION=$(chromium-browser --version | awk '{print $2}')
        echo "Using Chromium"
    else
        echo "Neither Chrome nor Chromium found. Please install one and try again."
        exit 1
    fi

    echo "Installed Chrome/Chromium version: $CHROME_VERSION"

    # Get the major version
    MAJOR_VERSION=$(get_major_version "$CHROME_VERSION")

    # Determine the operating system
    OS=$(uname -s)
    case $OS in
        Linux)
            OS_PATH="linux64"
            CHROMEDRIVER_FILE="chromedriver-linux64.zip"
            ;;
        Darwin)
            OS_PATH="mac-x64"
            CHROMEDRIVER_FILE="chromedriver-mac-x64.zip"
            ;;
        *)
            echo "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    # Construct the download URL
    DOWNLOAD_URL="https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/${OS_PATH}/${CHROMEDRIVER_FILE}"

    echo "Attempting to download ChromeDriver from: $DOWNLOAD_URL"

    # Try to download ChromeDriver
    if ! wget -O chromedriver.zip "$DOWNLOAD_URL"; then
        echo "Failed to download ChromeDriver for version $CHROME_VERSION"
        echo "Trying with major version only..."
        
        # Construct the download URL with major version only
        DOWNLOAD_URL="https://storage.googleapis.com/chrome-for-testing-public/${MAJOR_VERSION}.0.0.0/${OS_PATH}/${CHROMEDRIVER_FILE}"
        
        echo "Attempting to download ChromeDriver from: $DOWNLOAD_URL"
        
        if ! wget -O chromedriver.zip "$DOWNLOAD_URL"; then
            echo "Failed to download ChromeDriver. Please check your Chrome/Chromium version and try again."
            exit 1
        fi
    fi

    # Extract ChromeDriver
    unzip -o chromedriver.zip

    # Make ChromeDriver executable
    chmod +x chromedriver-*/chromedriver

    # Move ChromeDriver to /usr/local/bin (may require sudo)
    sudo mv chromedriver-*/chromedriver /usr/local/bin/

    # Clean up
    rm -rf chromedriver.zip chromedriver-*/

    echo "ChromeDriver for Chrome/Chromium version $CHROME_VERSION has been installed to /usr/local/bin/chromedriver"

    # Verify installation
    chromedriver --version
