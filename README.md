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
