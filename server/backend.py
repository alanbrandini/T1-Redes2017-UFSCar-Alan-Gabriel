# Cliente TCP
import socket
'''
	Funcao packetSender():
		Funcao que realiza o envio dos pacotes para os daemons e retorna suas
		respostas. Recebe como parametro a lista de instrucoes (vinda de webserver.py)
'''
	
def packetSender(instructionsList, ipAddress):
	
	for instruction in instructionsList:
		
		daemon_port = 8000 + instruction[0]
		
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# Tentativa de enviar o pacote para o deamon da instrucao
		try:
			s.connect((ipAddress, daemon_port))
			s.send(instruction[1])
		finally:	
			s.close()
		