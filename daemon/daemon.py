#Daemon - programa a ser replicado em cada maquina para executar os comandos
# Funcoes duplicadas em relacao ao backend.py para que funcione com qualquer backend 

import socket

'''
	Funcao ip2bin(ip):
		Retirada de https://stackoverflow.com/questions/2733788/convert-ip-address-string-to-binary-in-python
		Funcao para conversao de endereco IP (string) para binario 
'''

def ip2bin(ip):
    octets = map(int, ip.split('/')[0].split('.')) 			# '1.2.3.4'=>[1, 2, 3, 4]
    binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*octets)
    range = int(ip.split('/')[1]) if '/' in ip else None
    return binary[:range] if range else binary

'''
	Funcao bin2ip(ip):
		Funcao para conversao de binario para endereco IP (string)
'''
	
def bin2ip(ip):
	return '.'.join(str(int(ip[8*i:8*i+8],2),) for i in range(0,4))

'''
	Funcao decode_string_binary(s):
		Retirada de https://stackoverflow.com/questions/18815820/convert-string-to-binary-in-python
		Funcao para conversao de texto (string) para binario 
'''

def decode_string_binary(s):
	return ''.join(format(ord(x), 'b') for x in s)
	
'''
	Funcao decode_binary_string(s):
		Retirada de https://stackoverflow.com/questions/40557335/binary-to-string-text-in-python
		Funcao para conversao de binario para texto (string) 
'''

def decode_binary_string(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))
	
'''
	Funcao checksum(packet):
		Funcao que calcula o checksum do cabecalho. Validada com base no exmeplo do livro  Computer Network (James
		Kurose), capitulo 3, pagina 203.
'''

def checksum(packet):
	checksum = 0 										# Soma inicial = 0
	for i in xrange(1, len(packet), 16):				# Seleciona de 16 em 16 bits 
		checksum = checksum + int(packet[i-1:i+15],2) 	# Soma o checksum com os proximos 16 bits 
		if not ((checksum >> 16) == 0):					# Se houver overflow
			checksum = checksum + 1						#	Soma um 1 ao checksum 
			checksum = (checksum & int(0xFFFF))			# 	Tira o bit de overflow 
	checksum = int(checksum ^ 65535)					# Realiza o complemento de 1 (atraves de uma xor com 0xFFFF) 
	return bin(checksum)[2:].zfill(16)								# Retorna o checksum em binario 
	
'''
	Funcao vChecksum(packet):
		Funcao que verifica o checksum do cabecalho. Validada com base no exmeplo do livro  Computer Network (James
		Kurose), capitulo 3, pagina 203.
'''

def vChecksum(packet):
	checksum = 0 										# Soma inicial = 0
	for i in xrange(1, len(packet), 16):				# Seleciona de 16 em 16 bits 
		checksum = checksum + int(packet[i-1:i+15],2) 	# Soma o checksum com os proximos 16 bits 
		if not ((checksum >> 16) == 0):					# Se houver overflow
			checksum = checksum + 1						#	Soma um 1 ao checksum 
			checksum = (checksum & int(0xFFFF))			# 	Tira o bit de overflow 
	if checksum == int(0xFFFF):
		return True
	else:
		return False 

'''
	Funcao packetConstructor():
		Funcao que constroi o header do pacote. 
'''	

def packetConstructor(instruction, srcAddress_param, dstAddress_param, ttl_param, flags):

	# Definicao dos campos do pacote; nomes em maiusculo sao constantes
	VERSION = '0010' 								# Versao do protocolo = 2
	ihl = '0000'									# Inicialmente definido como 0, calculado abaixo com base no tamanho total do pacote 
	TOS = '00000000' 								# Type of Service, sempre sera 0
	total_length = '0000000000000000' 				# Tamanho total do pacote, calculado posteriormente
	identification = '0000000000000000'				# Numero de sequencia a ser checado com a resposta
	flag_type = flags								# Tres bits, marca se eh requisicao (000) ou resposta (111)
	FRAGMENT_OFFSET = '0000000000000'				# Treze bits, sempre sera 0
	header_checksum = '0000000000000000'			# Header Checksum, a ser calculado abaixo e conferido na entrega do pacote 
	srcAddress = ip2bin(srcAddress_param)			# Transforma o endereco IP de origem de string para o valor em binario
	dstAddress = ip2bin(dstAddress_param)			# Transforma o endereco IP de destino de string para o valor em binario
	options = decode_string_binary(instruction[2]) 	# Transforma o texto a ser enviado em options de  string para binario 

	# Campo Time to Live (ttl, altera o parametro ttl_param); se for requisicao, mantem; se for resposta, decrementa 1
	if (flag_type == '000'):
		ttl = ttl_param
	else:								# Se nao for do tipo requisicao, decrementa o tempo de vida
		ttl = format((int(ttl_param,2)-1), '08b')		# decremento de 1: transforma a str de bits para int e depois retorna para str de bits

	# Tratamento do campo de protocolo do cabecalho
	if (instruction[1] == 'ps'):
		protocol = '00000001'
	elif (instruction[1] == 'df'):
		protocol = '00000010'
	elif (instruction[1] == 'finger'):
		protocol = '00000011'
	elif (instruction[1] == 'uptime'):
		protocol = '00000100'	

	# Calculando IHL
	ihl = bin(len(VERSION+ihl+TOS+total_length+identification+flag_type+FRAGMENT_OFFSET+ttl+protocol+header_checksum+srcAddress+dstAddress+options)/32)[2:].zfill(4)	

	# Calculando o padding (quanto falta para completar a proxima palavra de 32 bits 
	if (len(options)%32 == 0):
		padding = '' 
	else:	
		padding = bin(0)[2:].zfill(32-(len(options)%32))

	# Calculando tamanho total (total_length) do pacote 
	total_length = bin(len(VERSION+ihl+TOS+total_length+identification+flag_type+FRAGMENT_OFFSET+ttl+protocol+header_checksum+srcAddress+dstAddress+options+padding))[2:].zfill(16)

	# Montar o pacote juntando todos os campos do cabecalho e retorna-o
	packet = VERSION+ihl+TOS+total_length+identification+flag_type+FRAGMENT_OFFSET+ttl+protocol+header_checksum+srcAddress+dstAddress+options+padding 

	# Calculando o checksum
	header_checksum = checksum(packet)

	# Montar o pacote juntando todos os campos do cabecalho e retorna-o
	return VERSION+ihl+TOS+total_length+identification+flag_type+FRAGMENT_OFFSET+ttl+protocol+header_checksum+srcAddress+dstAddress+options+padding 
	

HOST = ''              # Endereco IP do Servidor
PORT = 8001            # Porta que o Servidor esta
socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
origem = (HOST, PORT)
socket_tcp.bind(origem) 		# Torna visivel a porta do servidor para o cliente local conectar
socket_tcp.listen(1)			# Servidor passa a esperar por uma conexao do cliente 
while True:
    con, cliente = socket_tcp.accept() # Inicia conexao apos aceitar solicitacao do cliente 
    print 'Conectado por', cliente
    packet = con.recv(1024)
    print cliente, packet, vChecksum(packet)
    print 'Finalizando conexao do cliente', cliente
    con.close() 		# Encerra conexao