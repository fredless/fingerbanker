# fingerbanker

Full credit goes to [PiHole](https://github.com/Chrus3/PiHost) from which this repo was forked and
ultimately derived. Was looking to build a somewhat less sophisticated version of what that repo
provided to allow for automatic logging of devices in a format used by OpenWRT's `/etc/ethers` 
file on L2 APs.

## setup

Your linux host will need `tcpdump` installed.  You'll need to install some python packages used by
fingerbanker: `urllib3`, `requests`, and `scapy`.

## fingerbank

This script queries fingerbank to get a profile of the device based on DHCP and MAC particulars.
Create your own free account at https://fingerbank.org. Once that's done you'll need to get your
API key from the 'My Account' section.

## API key, INTERFACE value and ethers

Update the `API_KEY` and `INTERFACE` constants as appropriate.  You'll need a framework `ethers`
file for already known MAC addreses as the script assumes one exists.

## usage

```bash
sudo python3 fingerbanker.py
```

If all goes according to plan you'll see no output.  When DHCP queries come if they were not in the
'known' `ethers` file when the script started, fingerbank will be queried and a new entry written
to the `ethers_hints` file.  You can `tail -f ethers_hints` to watch the action.