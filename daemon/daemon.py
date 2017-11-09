#Daemon - programa a ser replicado em cada maquina para executar os comandos
# Servidor TCP
import socket
HOST = ''              # Endereco IP do Servidor
PORT = 8001            # Porta que o Servidor esta
socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
origem = (HOST, PORT)
socket_tcp.bind(origem) 		# Torna visivel a porta do servidor para o cliente local conectar
socket_tcp.listen(1)			# Servidor passa a esperar por uma conexao do cliente 
while True:
    con, cliente = socket_tcp.accept() # Inicia conexao apos aceitar solicitacao do cliente 
    print 'Conectado por', cliente
    msg = con.recv(1024)
    print cliente, msg
    print 'Finalizando conexao do cliente', cliente
    con.close() 		# Encerra conexao