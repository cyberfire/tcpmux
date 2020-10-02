tcpmux
=======
Enable to share the same TCP port for different applications, for example, http and ssh.

OVERVIEW
========


It is inspired by [@yrutschle](https://github.com/yrutschle/sslh) 's sslh project, but is implemented in a totally different way and works only on Linux operating system.

<pre>
The whole workflow is as below:

1. The program will listen on the common tcp port

2. A new connection arrives and will be accepted by tcpmux

3. The program will peek out the data of the first packet and check what protocol this connection is.
   
   The protocol identification code can be internal (or builtin-in) code, or external program.
   
   This enables to use more professional program to protocol identification
   
4. Once the protocol of the connection is set, the program will deliver the connection to real server, by.
    if the server is 1:N mode (one process will serve multiple clients, such as HTTP server), 
    the connection will be transfered to a TCP proxy server by UNIX socket. The TCP proxy server
    will take the client connection, establish a new connection with real server and forward 
    packets between the connection pairs.
    
    if the server is 1:1 mode, tcpmux will launch the real server and pass the connection fd to the real server.
    
This tcpmux framework is flexible to implement new features as could:
1. protocol identification
   the external protocol identification program is supported
                  Please refer to sample/sample_extern_ident.c
   it is also supported to register internal protocol identifier dyanmically 
                  please refer to sample/sample_xmodule.c 
2. access control: user can write access control program to limit IP and time to access one service. 
   Then configure tcpmux to launch this access control program instead of real server for a protocol. 
   After access check pass, the access control program can launch the real server.
   Please refer to sample/access_control.c

</pre>

BUILD
=======
<pre>
1. Install libconfig 
   In Ubuntu system, please use
         apt install libconfig-dev            
2. Compile
         make should work
    
    Files will be created:
    tcpmux ---- the main program
    sample/echo_srv --- a sample echo server for test
    sample/sample_xmodule.so --- a sample .so to demo how to register interanal protocol at run-time
    sample/sample_extern_ident --- a external identifier sample
    sample/tcp_proxy --- a tcp proxy to connect 1:N server
    sample/access_control --- a sample access control program
    sample/sampe_proxy --- implement a TCP proxy while embedded mulit-clients echo services.

</pre>
 
RUN
====
<pre>

 1. start the tcpmux
  sudo ./tcpmux -p listen_port  -d
  sudo: launch sshd needs root priviledge
  -p listen_port: optionally. If not present, this will get from config file: ./tcpmux.cfg
  -d:   run as daemon, optionally
  
 2. start the TCP proxy: (for HTTP) 
    ./sample/tcp_proxy -a http_ip -p http_port -d
    
 3. check configure file ./tcpmux.cfg if the ssh path is correct or not in your system
      {proto: "ssh";server:"/usr/sbin/sshd";para:"-i"},
 
 4.  do test
     4.1 test echo server first
     
     $cat > echo.txt &#60;&#60;  EOF
     echo
     hello, world
     could you hear me?
     Bye 
     EOF
     $nc 127.0.0.1 listen_port  &#60; echo.txt
     
     4.2 test ssh
     ssh 127.0.0.1  listen_port
     
     4.3 test HTTP
     wget 127.0.0.1 listen_port

</pre>
     
     
CONFIGURE FILE
===============
<pre>
The configure file is ./tcpmux.cfg and it is self-explainsive enough, I guess.
 
version = "1.0"
bind_addr= "0.0.0.0"
listen_port=8080
log_level=1 #1 --- info  2 --- debug

#set different protocol identifier programs here
#it could be internal one, built into or dynamic loaded by extension mode
# or an external program to parse the packet data
proto_identifier:
(
  #name "internal" is a reserved key word to stand for all internal identifiers
  {name:"internal";identifier:"internal";priority:0;disabled:0},
  {name:"open";identifier:"./open_ident";priority:1;disabled:1},
  {name:"extern0";identifier:"./sample/sample_extern_ident";priority:2;disabled:0}
)


extension_module:
(
   {name: "sample"; file: "./sample/sample_xmodule.so"}
)

#
# set the internal identifier's priroty and disable/enable
# name is the protocol identifier's name instead of protocol name
#
internal_identifer:
(
   {name: "http";priority:0;disabled: 0},
   {name: "echo";priority:1;disabled: 0},
   {name: "ssh";priority:1;disabled: 0},
   {name: "xecho";priority:2;disabled: 1},  #xecho, xssh is imported by sample_xmodule.so
   {name: "xssh";priority:2;disabled: 0}
)

#if the same protocol handler is defined both in proxy_server and in proto_server
#proxy server handler will  be called first 

proxy_server:
(
   {proto:"http"; channel:"/tmp/unix.proxy.0"}
)


proto_server:
(
   #sample to launch sshd directly
   #{proto: "ssh";server:"/usr/sbin/sshd";para:"-i"},
   #sample to add an access check in pipe
   {proto: "ssh";server:"./sample/access_control";para:"ssh,/usr/sbin/sshd,-i"},
   {proto: "echo"; server:"./sample/echo_srv"}
)

</pre>

TODO
====

<pre>
1. protocol identification
   I'm trying to find open source protocol identification and porting to the project. 
   But I do not find out a good one yet.
   
   The samples currently implemented are too simpled and too easy to be attacked.
         
2. install scripts and packages
   I'm not familiar on this part yet.
 </pre>
  
     
  
 
 
  
    









