#!/usr/bin/env python
import cgi 
import cgitb
import backend
cgitb.enable()

'''
	Funcao getData(form):
		funcao para tratar os dados enviados pelo form, montando uma colecao de itens com as intrucoes (com suas
		respectivas opcoes) a serem executadas em cada uma das maquinas.
'''

def getData(form):
	
	results = []			# Colecao de itens que recebe as instrucoes (com opcoes) para cada uma das maquinas
							# A passagem de instrucao para protocolo (ex.: ps para 1) sera feita adiante
							
	for field in form:
		if '_' in field and field != 'submit': 
			results.append([int(field[3]),field[5:], form.getvalue(field.replace('_','-'),'')])
	
	return results

form = cgi.FieldStorage() 				# Pega os dados submetidos

print("Content-Type: text/html;charset=utf-8\r\n\r\n")   
	
instructionsList =  getData(form)

# Chamada da funcao do backend para enviar as instrucoes para os daemons
# print '<p> Resposta: ', backend.packetSender(instructionsList, '127.0.0.1'), '</p>'

try:
	answerList = backend.packetSender(instructionsList, '127.0.0.1') # Envia dados da pagina para backend e atribui as respostas a variavel
	for answer in answerList:
		print '<p>', answer[0], ' ', answer[1], '</p>'
		dataResponses = answer[2].split('\n')
		
		for data in dataResponses:
			print '<p style = "margin-left: 30px;">', data, '</p>'
except ValueError:
	print '<p> Falha ocorrida. Pacote mal-enviado. Verifique os argumentos e tente novamente. </p>'
