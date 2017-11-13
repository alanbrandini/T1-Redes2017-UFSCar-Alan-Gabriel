#!/usr/bin/env python
import cgi 
import cgitb
import backend
import time
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
		if '_' in field and field != 'submit': 													# Ignora o 'submit'
			results.append([int(field[3]),field[5:], form.getvalue(field.replace('_','-'),'')]) # Remove _ e -
	
	return results

form = cgi.FieldStorage() 				# Pega os dados submetidos

# Impressao da pagina html 
print ("Content-Type: text/html;charset=utf-8\r\n\r\n")   
print ("<!DOCTYPE HTML> ")
print ("<html>")
print ("<head>  <style type=\"text/css\">  html, body ,a{  background:#000000;  color:#00FF00;  font-family:monospace;  height: 100%;  text-decoration:  none;} .footer {margin:auto;     height:40px;    clear:both; margin-left: 40%;} .btnStyle{-webkit-transition-duration: 0.4s; / Safari */     transition-duration: 0.4s; font-size:24px; background-color: #4CAF50; border:2px solid #4CAF50;; color:white; width:50%;} .btnStyle:hover{background-color: black;  color: #00FF00;}</style>")
print ("<title> T1 - Redes - Alan e Gabriel </title>")
print ("</head>")

print ("<body>")
	
instructionsList =  getData(form) 	# Trata as respostas do html e coloca e instructionsList
timeStart = time.time() 			# Retorna tempo de inicio
# Impressao das respostas em html 
try:
	answerList = backend.packetSender(instructionsList, '127.0.0.1') # Envia dados da pagina para backend e atribui as respostas a variavel
	timeFinish = time.time()
	print '<h2 style= "text-align: center;"> Resultados (em ', (timeFinish-timeStart)*1000, ' ms): </h2> <hr style= "border-color: green;">' 
	for answer in answerList:
		print '<p>', answer[0], ' ', answer[1], '</p>'
		dataResponses = answer[2].split('\n')
		
		for data in dataResponses:
			print '<p style = "margin-left: 30px;">', data, '</p>'
except ValueError:
	print '<p> Falha ocorrida. Pacote mal-enviado. Verifique os argumentos e tente novamente. </p>' # Tratamento de erro de envio de pacote

# Botao de voltar
print("<div id='menu' class=\"footer\">         <table width=\"50%\">         <tr>           <td>")
print("<form> <input type=\"button\" class =\"btnStyle\" value=\"Voltar\" onClick=\"history.go(-1)\"> </form>")
print("</td></tr></table>")

print("</body> </html>")