# setup via python env
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

# install tools
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@latest

# run
uvicorn app.main:app --port 8000
