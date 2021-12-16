BEFORE COMPILING
In the Client.java file:
	-change the "filepath" and "keypath" strings to your filepath to the "Client Files" and "Keys" folders in your directories
In the Server.java file:
	-change the "filepath" and "keypath" strings to your filepath to the "Server Files" and "Keys" folders in your directories
In the ssh.sh file:
	-change "netid" to your netid


TO COMPILE
 -Run make.sh
 -Create two instances of putty or whatever ssh you are using to the UTD servers
 -Run ssh.sh in both instances of putty
 -cd into whatever directory the files are on both instances
 -On one of the putty instances, run "java Server"
 -Then, on the other instance of putty, run "java Client" IN THAT ORDER
 -Use the program
	