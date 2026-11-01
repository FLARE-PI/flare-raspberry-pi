### ABAC
Command-line tool to manage the ABAC linux security module.

### Installation
1. Install dependencies (python3, pip and setuptools)
```bash
# On debian
sudo apt install python3-pip
pip install setuptools

# On Fedora
sudo dnf install python3-pip python3-wheel
pip install setuptools

# For other distributions, please refer to your distributions manual/documentation
```

2. Run the installation script (requires root previleges)
```bash
chmod +x install.sh
su
./install.sh
```

3. Verify that the abac command is available
```bash
which abac
```

4. Verify that the Systemd services are up and running
```bash
systemctl status abac.service
systemctl status abac_env.service
systemctl status abac_watch.service
```

### Path Scope
By default, installation initializes `/home/secured/` as the first ABAC include path.
You can configure protected scope with:

```bash
sudo abac scope list
sudo abac scope add -t include /srv/data
sudo abac scope add -t exclude /srv/data/tmp
sudo abac scope delete -t include /home/secured
sudo abac scope load
```

### Usage
The abac cli tool contains ALL the tool required for managing attributes and policies.  
The cli tool can be invoked using the `abac` command followed by specific commands such as `user, obj` etc.  
The main functions of the tool are explained below -   
1. `abac obj` - Manage object attributes. The available functions are `add, list, change, delete`.
2. `abac user` - Add, remove and manage users and their attributes. The available functions are `add, list, delete, manage`.
3. `abac policy` - Manage the ABAC policy. The available functions are `add, list, delete`.
4. `abac avp` - Add available attribute value pairs for objects and users. The available functions are `add, list, delete, modify`.
5. `abac load` - Load the abac attributes and policy into the kernel.
6. `abac scope` - Manage ABAC include/exclude path scope.
7. `abac server` - Start the ABAC attribute server. This is automaticlly done by the systemd service.
8. `abac init` - Initialize the abac config directory. This is automatically done during installation.

For each of the above subcommands, passing the flag `--help` prints the required help.
None of the above subcommands, except `abac obj` are available to normal users.

### Directory Inheritance
Object attributes assigned to a directory are inherited by files and
subdirectories below it. More specific paths override less specific ones for the
same attribute name.

Example:

```bash
sudo abac scope add -t include /srv/finance
abac obj add /srv/finance
```

If `/srv/finance` is given an object attribute such as `domain=finance`, then
rules matching `obj.domain=finance` will apply to files inside that directory
unless a more specific child path overrides that attribute.
