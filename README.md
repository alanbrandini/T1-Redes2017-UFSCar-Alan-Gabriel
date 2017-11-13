# T1-Redes2017-UFSCar-Alan-Gabriel
Primeiro Trabalho da disciplina de Redes de Computadores da UFSCar, ministrada no segundo semestre de 2017. 
Abaixo encontra-se a descrição do projeto.

## Descrição do Projeto
<p align="justify">O projeto consiste na implementação de uma aplicação <i>cliente-servidor</i>, a qual permitirá ao usuário realizar a execução de um comando num conjunto de "máquinas" Linux utilizando uma interface <i>web</i> (em <i>python</i>). Numa página <i>html</i>, o usuário poderá selecionar comandos de uma lista, sendo eles <i>ps</i>, <i>df</i>, <i>finger</i> e <i>uptime</i>, e adicionar parâmetros a eles. Enviados os comandos e estes recebidos pela interface <i>web</i>, um aplicativo <i>backend</i> (também em <i>python</i>) conectará-se com um conjunto de "<i>daemons</i>" rodando em cada uma das "máquinas". Estes últimos irão executar os comandos direcionados a cada uma das respectivas máquinas localmente e reenviarão as respostas para o <i>backend</i>, que exibirá as respostas na interface <i>web</i>. </p>

## Executando a Aplicação
**1. Disposição dos arquivos** <br>
Pode-se dispor os arquivos de duas maneiras:
- Copiar o arquivo <i>daemonStart.sh</i> para <code>cgi-bin</code> e copiar todos os arquivos dos diretórios <code>server/</code> e <code>daemon/</code> para <code>/usr/lib/cgi-bin</code> e alterar os caminhos do arquivo <i>daemonStart.sh</i> de <code>/usr/lib/cgi-bin/daemon/daemon.py</code> para <code>/usr/lib/cgi-bin/daemon.py</code>; ou
- Copiar o arquivo <i>daemonStart.sh</i> e copiar os diretórios <code>server/</code> e <code>daemon/</code> para dentro do diretório <code>/usr/lib/cgi-bin</code> e alterar a linha <b>14</b> do arquivo <code>/var/www/html/index.html</code> de <code>\<form method=POST action="cgi-bin/webserver.py"></code> para <code>\<form method=POST action="cgi-bin/server/webserver.py"></code>.
  
**2. Alteração das permissões dos arquivos** <br>
Para poder executar a aplicação, será necessário alterar a permissão dos arquivos <i>.py</i> e <i>.sh</i>. Dessa forma, execute os seguintes comandos no terminal: <br>
```
sudo chmod 775 <path-to-file>/daemon.py
sudo chmod 775 <path-to-file>/webserver.py
sudo chmod 775 <path-to-file>/backend.py
sudo chmod 775 <path-to-file>/daemonServer.sh
```

**3. Execução dos <i>daemons</i>** <br>
Assim que os arquivos forem dispostos como descrito em <b>1.</b> acima, pode-se executar os <i>daemons</i>, através da execução de <i>daemonStart.sh</i>. Para isso, execute-o através da linha de comando: <br> <code>usr/lib/cig-bin/daemonStart.sh</code> <br> Assim, os <i>daemons</i> estão configurados e prontos para receber os comandos da interface <i>web</i> (através do <i>backend</i>).

**4. Envio de comandos para execução** <br>
Para enviar os comandos, basta acessar a página <i>html</i> a partir de seu navegador (colocando o IP obtido da máquina virtual - pode-se executar <code>ifconfig</code> para descobri-lo) e selecionar o(s) <i>checkbox(es)</i> do(s) comando(s) a ser(em) executado(s) na(s) máquina(s) desejada(s) e inserir os parâmetros no(s) <i>textbox(es)</i> (se for o caso). Assim que estiver satisfeito, basta clicar em <b>Enviar</b>. O usuário será redirecionado para uma página de respostas. Caso deseje limpar os comandos selecionados, basta clicar em <b>Limpar</b>.
