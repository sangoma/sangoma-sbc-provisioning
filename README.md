
# Sangoma SBC Initial Provisioning for Carriers

## Getting started

This software provisions a newly installed system by performing initial
configuration and registering the configured system on an EMS server.

The parameters and EMS server options come from a file in ToML format.

A sample ToML configuration file is provided on the provisioning package,
which needs to be renamed from "config-sample.toml" to "config.toml" and
placed in the root directory of the USB key OR the /provisioning directory
(whichever is being used for provisioning). Options required for initial
setup are documented in this sample file, which also has defaults for
most parameters.

There are a few differente "actions" supported, which are all executed
in the following order if no action is specified:

* update: Updates the system to the latest version (if required);
* config: Configures the system using information in "config.toml";
* request: Registers the current system in the EMS server;
* restore: Restores extra configuration from a template file (if specified).

The "request" action also supports some commands passed via command line,
which override the values found in the configuration file (if specified).

The "restore" action (optional) will restore additional system configuration
from the configuration backup file passed to the "--template" comand line
option. If this option is not provided, the step is skipped.

Some options can be automatically inferred: a special format is supported
for a few parameters section "EMS", namely "ip", "macid", "altmacid" and
"mediamacid". For these parameters, passing a network device name between
parenthesis will automatically find the option from the interface, either
using the first static IP on the interface (for "ip") or the MAC address
or the interface (*macid options).

First step is to adjust "config.toml" as required:

```
  # <favourite-editor> config.toml
```

Provisioning is performed by calling the "configure.sh" script, which runs
all the steps required for initial configuration and registration on the EMS
server.

Second step is to run the script - by default, calling it without any
arguments will perform all the required steps automatically:

```
  # ./configure.sh
```

A few command line parameters are supported (shown below).


## Command line usage and options:

```
  ./configure.sh [action] [provisioning-options] -- [request-options]

  action:
    all         perform all required provisioning actions (default)
    update      check current version and perform update, if needed
    config      check current configuration and apply new options, if needed
    ems         register current server on EMS service
    restore     restore the configuration backup from a template,
                skipping network, license and REST API

  provisioning-options:

    --template FILE  use FILE as a template backup package to restore from

    --dump           dump the configuration data and exit

    --force-apply    apply and restart network even if no changes have been made
    --no-restart     do not restart the network after configuration

    --no-patches     do not apply any patches on system
    --copy-update    also copy update package when installing on /provisioning

  request-options:

    --ip          IP address of the SBC (same IP used for connecting to EMS)
    --server      Server socket where request should be sent
    --key         REST API key
    --current     An identifier used to validate the API call
    --macid       MAC address of the primary ethernet port
    --name        An unique name for the SBC
    --description Description for the particular SBC
    --venue       Information on the location of the SBC
    --altmacid    MAC address of secondary ethernet port, if any
    --mediamacid  MAC Address of media interface
    --hdserial    Serial number of the hard disk
    --ca          PEM file for secure connection (HTTP is used if not present)
    --config      Alternativelly, a config file (.ini) with command line parameters.
                  Command line parameters override parameters on config file
```


## SBC Pre-Provisioning Step-by-Step

### SBC pre-provisiong package contains three items 
Located at ftp://ftp.sangoma.com/nsc/2.3/provisioning/

1. config-sample.toml 
2. SBC upgrade binary
3. Provisioning scripts

### Create USB Key

1. Copy SBC pre-provisioning package to a USB KEY
2. Copy config-sample.toml to config.toml
3. Edit config.toml and specify SBC configuration

### Connect Laptop to SBC

1. Connect a Laptop to SBC via USB to RJ45 baby blue cable
2. Open Putty and select a Serial COM port
 * Device manager will display exact USB-Serial com port to use
 * Specify 115200n81 configuration
3. Log into the SBC using default credentials 
 * root/sangoma
4. Connect USB Key to Sangoma SBC USB port
5. Mount USB
 * Enterprise and SMB SBC: mount /dev/sdb1 /mnt
 * Carrier SBC: mount /dev/sdc1 /mnt
6. Change directory to /mnt
7. Unzip the provisioning package
 * tar xfz provisioning-<version>.tgz
8. Change directory to provisioning directory

### Run Configuration

1. Run: ./configure.sh
 * Contents of USB will be copid to /provisioing directory
 * Configure will proceed to upgrade firmware 
 * After firmware update the SBC will reboot

After reboot proceed to /provisioning directory, there is no need to work from USB any more.

1. Log in
2. cd /provisioning
3. Run: ./configure.sh
 * This step will proceed with intial configuraiton
  ** networking, user, notifications
4. If EMS is configured
 * SBC will try to connect to EMS

At this point SBC should be able to connect to the LAN or Internet.

1. Connect to SBC GUI via IP
2. Proceed with the rest of the configuration


# License

Distributed under the GNU GPL 2 (see LICENSE file)

Copyright (C) 2016 Sangoma Technologies Corp.
