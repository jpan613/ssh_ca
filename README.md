# SSH CA

This is a prototype of a SSH certificate CA based the some of the ideas described here:

[Introducing the Uber SSH Certificate Authority](https://medium.com/uber-security-privacy/introducing-the-uber-ssh-certificate-authority-4f840839c5cc)

The general workflow of this CA is to allow users to ssh to a CA host with the ssh-agent forwarded, if the user authenticates successfully and belongs to the proper group that's authorized to request the certificate, the CA runs ssh_ca which generates the client key pair, sets up the certificate (principal based on the logged in username), and then signs it with its ca private key, and then add the client private key + the signed certificate to the forwarded ssh-agent. The user, with the added identity in the ssh-agent, can now ssh into other hosts that trust this CA's public key.

Setup:

* Client:

   * you need to modify ~/.ssh/config to allow the agent to be forwarded to all the hosts in this setup:
   ```
   Host <prod_host_name_wildcard>
      ForwardAgent yes
   ```

* CA:

  * Have the proper pam authentication for sshd set up on the CA host, the CA is the only server that we should use password +  some kind of TOTP for authentication.
  * Create a group (let's say it's called ssh_ca_group)  that is authorized to request the certificate and add users to them.
  * Generate the CA key pair by
  ```
  ssh-keygen -t ed25519 -f /etc/ssh/ca
  ```
  * add the compiled binary of ssh_ca to /usr/bin/
  * add
    ```
    Match Group ssh_ca_group
	     ForceCommand ssh_ca -cakeypath /etc/ssh/ca
    ```
    to /etc/ssh/sshd_config
    This will run ssh_ca if the user authenticates successfully, and is in the ssh_ca_group; after ssh_ca runs, the user will get logged off immediately.

* Server:

   * For all the servers that the users should be able to ssh into using their certificate obtained from the CA, copy /etc/ssh/ca.pub off the CA, and then copy to /etc/ssh on these servers, and add
```
TrustedUserCAKeys /etc/ssh/ca.pub
```
to /etc/ssh/sshd_config


The benefits of using ssh certificates over ssh keys are well documented:
[OpenSSH Certificate](https://blog.habets.se/2011/07/OpenSSH-certificates.html)

On top of that, this approach allows admins to use the well understood authentication and authorization built into ssh and pam to securely issue time-bound ephemeral access to the users without actually storing any credential on disk.

* Demo

```
laptop:ssh_ca jp$ ssh-add -D
All identities removed.
laptop:ssh_ca jp$ ssh-add -L
The agent has no identities.
laptop:ssh_ca jp$ ssh user1@ca
user1@ca's password:
Duo two-factor login for user1

Enter a passcode or select one of the following options:

 1. Duo Push to XXX-XXX-XXXX

Passcode or option (1-1):




Generated ed25519 key pairs with the public key of:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO5vumNCUOBZ5iSg0gYxLlCzXDCI2mwBsKPq+RwatDXA

Current username [user1] will be used as certificate principal

Signed certificate successfully with [/etc/ssh/ca]

adding certificate to ssh-agent

added certificate to ssh-agent, please run ssh-add -L to verify

Connection to ca closed.
laptop:ssh_ca jp$ ssh-add -L
ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIB1JzmuXuBr16il4UFt6BX+LYFt6AdeAAOgkbQiNFD76AAAAIO5vumNCUOBZ5iSg0gYxLlCzXDCI2mwBsKPq+RwatDXATWWCIQf8/VIAAAABAAAAAAAAAAkAAAAFdXNlcjEAAAAAWzqKYgAAAABbOsKiAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgImpfLxJ5XmjQrg5SL0CuAZCJL4JAFK7HQKfDtrZ9HK4AAABTAAAAC3NzaC1lZDI1NTE5AAAAQLrOcO1Gz+8uelltsfJ2W4XBee1dyrENs8x4RqXqcCz20clQdg2KDQuiyJNmRiaE11gt9C4Pe/dtII3CxTjm0AE=
laptop:ssh_ca jp$ ssh user1@host1
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-127-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  Get cloud support with Ubuntu Advantage Cloud Guest:
    http://www.ubuntu.com/business/services/cloud

42 packages can be updated.
28 updates are security updates.


Last login: Mon Jul  2 17:33:48 2018 from
user1@host1:~$
```
