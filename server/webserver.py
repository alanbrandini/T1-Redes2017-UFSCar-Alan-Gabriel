#!/usr/bin/env python
import cgi 
import cgitb
# import backend
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

# Tratamento das keys
formKeys = form.keys()					# Pega as Keys dos dados submetidos
if 'submit' in formKeys:
	formKeys.remove('submit')			# Remove a Key Submit, enviada atraves do botao 'enviar'

print("Content-Type: text/html;charset=utf-8\r\n\r\n")
print ("Olar<br>")    
print("Hello World!<br><br>")
for keys in formKeys: 
	print'<p>name: ', keys, '</p>'
print list(formKeys)
print("<br>") 

print list(form) 	
print '<p>', getData(form), '</p>' 

# print '<p> Teste para o Alan: ', form.getvalue('maq1-ps')

# backend.passaParametro('Me comuniquei! Hello World!')