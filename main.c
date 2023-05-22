#ifdef _WIN32
	#define _WIN32_WINNT _WIN32_WINNT_WIN7
	#include <winsock2.h> //for all socket programming
	#include <ws2tcpip.h> //for getaddrinfo, inet_pton, inet_ntop
	#include <stdio.h> //for fprintf, perror
	#include <unistd.h> //for close
	#include <stdlib.h> //for exit
	#include <string.h> //for memset
	void OSInit( void )
	{
		WSADATA wsaData;
		int WSAError = WSAStartup( MAKEWORD( 2, 0 ), &wsaData ); 
		if( WSAError != 0 )
		{
			fprintf( stderr, "WSAStartup errno = %d\n", WSAError );
			exit( -1 );
		}
	}
	void OSCleanup( void )
	{
		WSACleanup();
	}
	#define perror(string) fprintf( stderr, string ": WSA errno = %d\n", WSAGetLastError() )
#else
	#include <sys/socket.h> //for sockaddr, socket, socket
	#include <sys/types.h> //for size_t
	#include <netdb.h> //for getaddrinfo
	#include <netinet/in.h> //for sockaddr_in
	#include <arpa/inet.h> //for htons, htonl, inet_pton, inet_ntop
	#include <errno.h> //for errno
	#include <stdio.h> //for fprintf, perror
	#include <unistd.h> //for close
	#include <stdlib.h> //for exit
	#include <string.h> //for memset
	void OSInit( void ) {}
	void OSCleanup( void ) {}
#endif

#define debug

int initialization();
int connection( int internet_socket );
void execution( int internet_socket );
void cleanup( int internet_socket, int client_internet_socket );
char ip_lookup[30];


int main( int argc, char * argv[] )
{
	while(1){

	
	//////////////////
	//Initialization//
	//////////////////

	OSInit();

	int internet_socket = initialization();
	//printf("init\n");
	//////////////
	//Connection//
	//////////////
	printf("waiting on connection on port 22:\n");
	int client_internet_socket = connection( internet_socket );
	
	/////////////
	//Execution//
	/////////////

	execution( client_internet_socket );


	////////////
	//Clean up//
	////////////

	cleanup( internet_socket, client_internet_socket );

	OSCleanup();
	}
	return 0;
}

int initialization()
{
	//Step 1.1
	



	struct addrinfo internet_address_setup;
	struct addrinfo * internet_address_result;
	memset( &internet_address_setup, 0, sizeof internet_address_setup );
	internet_address_setup.ai_family = AF_UNSPEC;
	internet_address_setup.ai_socktype = SOCK_STREAM;
	internet_address_setup.ai_flags = AI_PASSIVE;
	int getaddrinfo_return = getaddrinfo( "::1", "22", &internet_address_setup, &internet_address_result );
	if( getaddrinfo_return != 0 )
	{
		fprintf( stderr, "getaddrinfo: %s\n", gai_strerror( getaddrinfo_return ) );
		exit( 1 );
	}

	int internet_socket = -1;
	struct addrinfo * internet_address_result_iterator = internet_address_result;
	while( internet_address_result_iterator != NULL )
	{
		//Step 1.2
		internet_socket = socket( internet_address_result_iterator->ai_family, internet_address_result_iterator->ai_socktype, internet_address_result_iterator->ai_protocol );
		if( internet_socket == -1 )
		{
			perror( "socket" );
		}
		else
		{
			//Step 1.3
			int bind_return = bind( internet_socket, internet_address_result_iterator->ai_addr, internet_address_result_iterator->ai_addrlen );
			if( bind_return == -1 )
			{
				perror( "bind" );
				close( internet_socket );
			}
			else
			{
				//Step 1.4
				int listen_return = listen( internet_socket, 1 );
				if( listen_return == -1 )
				{
					close( internet_socket );
					perror( "listen" );
				}
				else
				{
					break;
				}
			}
		}
		internet_address_result_iterator = internet_address_result_iterator->ai_next;
	}

	freeaddrinfo( internet_address_result );

	if( internet_socket == -1 )
	{
		fprintf( stderr, "socket: no valid socket address found\n" );
		exit( 2 );
	}

	return internet_socket;
}

int connection( int internet_socket )
{
	//Step 2.1
	struct sockaddr_storage client_internet_address;
	socklen_t client_internet_address_length = sizeof client_internet_address;
	int client_socket = accept( internet_socket, (struct sockaddr *) &client_internet_address, &client_internet_address_length );
	if( client_socket == -1 )
	{
		perror( "accept" );
		close( internet_socket );
		exit( 3 );
	} 

			//finding out the ip address
			char client_ip[INET6_ADDRSTRLEN]; // This can accommodate both IPv4 and IPv6 addresses
			if (client_internet_address.ss_family == AF_INET)
			{
				struct sockaddr_in *s = (struct sockaddr_in *)&client_internet_address;
				inet_ntop(AF_INET, &(s->sin_addr), client_ip, sizeof client_ip);
			}
			else if (client_internet_address.ss_family == AF_INET6)
			{
				struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client_internet_address;
				inet_ntop(AF_INET6, &(s->sin6_addr), client_ip, sizeof client_ip);
			}
			else
			{
				fprintf(stderr, "Unknown address family\n");
				close(client_socket);
				close(internet_socket);
				exit(4);
			}

			//printf("connected, ip: %s\n", client_ip);
			#ifndef debug
			strcpy(ip_lookup, client_ip);
			#endif
			#ifdef debug
			strcpy(ip_lookup, "94.110.92.242");
			#endif

			char BigLine[] = "=================================================\n";
			char logbuffer[1000];
			FILE *logp;
			logp = fopen("IPLOG.txt", "a");
			if(logp != NULL){
				snprintf(logbuffer, sizeof(logbuffer), "%sIP address of attacker: %s\n", BigLine, ip_lookup);
				fprintf(logp, logbuffer);
			}
			fclose(logp);


			//sending a string with curl and the url in CLI, and reading the output file from popen();
			char CLI_buffer[1000];
			snprintf(CLI_buffer, sizeof(CLI_buffer),"curl http://ip-api.com/json/%s?fields=1561", ip_lookup);
			FILE *fp;
    		char IP_LOG_ITEM[2000];

    		fp = popen(CLI_buffer, "r");
    		if (fp == NULL) {
        	printf("Error opening cli buffer\n");
        	return client_socket;
    		}
			fgets(IP_LOG_ITEM, sizeof(IP_LOG_ITEM)-1, fp);
			
			system("clear");
			printf(logbuffer);
			//printf("%s\n", IP_LOG_ITEM);
    		//}
    		pclose(fp);

			//{"country":"Belgium","regionName":"Flanders","city":"Genk","isp":"Mobistar Cable","org":"Mobistar Enterprise Services"}
			if(IP_LOG_ITEM[1] != '}'){
			char country[50];
			char regionName[50];
			char city[50];
			char isp[50];
			char org[50];
				
			//sscanf(IP_LOG_ITEM, "{\"country\":\"%s\",\"regionName\":\"%s\",\"city\":\"%s\",\"isp\":\"%s\",\"org\":\"%s\"}",country, regionName,city, isp, org);
			//snprintf(IP_LOG_PARSED, sizeof(IP_LOG_PARSED), "Country: %s\nRegion: %s\nCity: %s\nISP: %s\nOrganisation: %s\n",country, regionName,city, isp, org);
			
			
			//parsing the json, not clean, but it works....
			logp = fopen("IPLOG.txt", "a");
			if(logp != NULL){
				char logbuffer[1000];
				for (int i = 0; IP_LOG_ITEM[i] != '\0'; i++)
			{
				if(IP_LOG_ITEM[i]== ','){
				fprintf(logp, "\n");
				printf("\n");
				}else if(IP_LOG_ITEM[i] == ':'){
				fprintf(logp, ": ");
				printf(": ");
				}else if(IP_LOG_ITEM[i] == '{' || IP_LOG_ITEM[i] == '}'){
				}else if(IP_LOG_ITEM[i] == '"' || IP_LOG_ITEM[i] == '"'){
				}else{
				fprintf(logp, "%c", IP_LOG_ITEM[i]);
				printf("%c", IP_LOG_ITEM[i]);
				}

				
			}
			fprintf(logp, "\n");
			 printf("\n");
				
			}
			fclose(logp);
			}


		return client_socket;
}

void execution( int internet_socket )
{
	int number_of_bytes_received = 0;
	char buffer[2000];
	

	
		number_of_bytes_received = recv( internet_socket, buffer, ( sizeof buffer ) - 1, 0 );
	if( number_of_bytes_received == -1 )
	{
		perror( "recv" );
	}
	else
	{
		buffer[number_of_bytes_received] = '\0';
		printf( "Received : %s\n", buffer );
	}
	for (int i = 0; i < 1000; i++)
	{	
	char chartosend[] = "\nharambe loves you <3\n               _\n"
       "            ,.-\" \"-.,\n"
       "           /   ===   \\\n"
       "          /  =======  \\\n"
       "       __|  (o)   (0)  |__\n"
       "      / _|    .---.    |_ \\\n"
       "     | /.----/ O O \\----.\\ |\n"
       "      \\/     |     |     \\/\n"
       "      |                   |\n"
       "      |                   |\n"
       "      |                   |\n"
       "      _\\   -.,_____,.-   /_\n"
       "  ,.-\"  \"-.,_________,.-\"  \"-.,\n"
       " /          |       |          \\\n"
       "|           l.     .l           |\n"
       "|            |     |            |\n"
       "l.           |     |           .l\n"
       " |           l.   .l           | \\,\n"
       " l.           |   |           .l   \\,\n"
       "  |           |   |           |      \\,\n"
       "  l.          |   |          .l        |\n"
       "   |          |   |          |         |\n"
       "   |          |---|          |         |\n"
       "   |          |   |          |         |\n"
       "   /\"-.,__,.-\"\\   /\"-.,__,.-\"\\\"-.,_,.-\"\\\n"
       "  |            \\ /            |         |\n"
       "  |             |             |         |\n"
       "   \\__|__|__|__/ \\__|__|__|__/ \\_|__|__/\n";
	int number_of_bytes_send = 0;
	number_of_bytes_send = send( internet_socket, chartosend, strlen(chartosend), 0 );
	if( number_of_bytes_send == -1 )
	{
		perror( "send" );
		break;
	}else{
	printf("sent: %s\n", chartosend);
	}
	}
	//http://ip-api.com/json/%s?fields=country,regionName,city,isp
	
	
    /*
    strcpy(chartosend,IP_LOG_ITEM);
	number_of_bytes_send = 0;
	number_of_bytes_send = send( internet_socket, chartosend, strlen(chartosend), 0 );
	if( number_of_bytes_send == -1 )
	{
		perror( "send" );
		//break;
	}else{
	printf("sent: %s\n", chartosend);
	}
	*/
	}


void cleanup( int internet_socket, int client_internet_socket )
{
	//Step 4.2
	int shutdown_return = shutdown( client_internet_socket, SD_RECEIVE );
	if( shutdown_return == -1 )
	{
		perror( "shutdown" );
	}

	//Step 4.1
	close( client_internet_socket );
	close( internet_socket );
}