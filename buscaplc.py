import os
from shodan import Shodan
from censys.search import CensysHosts
from datetime import datetime
import time

api_shodan = Shodan('CHAVE DA AIP DO SHODAN')
api_censys = CensysHosts()


def apagar_arquivo():
    if os.path.exists('enderecos_ip.txt'):
        os.remove('enderecos_ip.txt')


def pesquisa_shodan(dados):
    hoje = datetime.today().strftime('%d/%m/%Y - %H:%M:%S')
    result = api_shodan.search(query=dados)
    with open(f'busca_{dados.split(" ")[2]}', 'a') as arquivo, open(f'enderecos_ip_{dados.split(" ")[2]}.txt', 'a') as arquivo2:
        arquivo.write(f'###########          SHODAN.IO           ###########\n\n')
        arquivo.write(f'########### RELATÓRIO INICIAL - {hoje} ###########\n\n')
        for i in result:
            if i == 'matches':
                for k in result[i]:
                    arquivo.write('------------------------------------------------------------------------\n')
                    arquivo.write(f'IP: {k["ip_str"]} - Porta: {k["port"]}\n')
                    arquivo2.write(f'{k["ip_str"]}\n')
                    arquivo.write(f'Organização: {k["org"]}\n')
                    arquivo.write(f'IPS: {k["isp"]}\n')
                    arquivo.write(f'ASN: {k["asn"]}\n')
                    if 'location':
                        arquivo.write(f'País: {k["location"]["country_name"]}\n')
                        arquivo.write(f'Estado: {k["location"]["region_code"]}\n')
                        arquivo.write(f'Cidade: {k["location"]["city"]}\n')
                        arquivo.write(f'Dados:\n {k["data"]}\n')
            time.sleep(10)
        tempo = datetime.today().strftime('%d/%m/%Y - %H:%M:%S')
        arquivo.write(f'########### FIM DO RELATÓRIO - {tempo} ###########')


def ip_shodan(dados):
    hoje = datetime.today().strftime('%d/%m/%Y - %H:%M:%S')
    with open(f'enderecos_ip_{dados.split(" ")[2]}.txt', 'r') as arquivo, open(f'relatorio_shodan_{dados.split(" ")[2]}.txt', 'a') as arquivo2:
        ip = arquivo.readlines()
        arquivo2.write(f'###########                 SHODAN.IO                   ###########\n')
        arquivo2.write(f'########### BUSCA POR ENDEREÇO IP - {hoje} ###########\n\n')
        for i in ip:
            consulta = f'ip:{i}'
            resultado_consulta = api_shodan.search(query=consulta)
            arquivo2.write(f'=====================\n')
            arquivo2.write(f'>>>>>  IP: {i}  <<<<<\n')
            arquivo2.write(f'=====================\n\n')

            for r in resultado_consulta:
                if r == 'matches':
                    for k in resultado_consulta[r]:
                        arquivo2.write('----- Serviço -----\n')
                        arquivo2.write(f'Porta: {k["port"]}\n')
                        arquivo2.write(f'Organização: {k["org"]}\n')
                        arquivo2.write(f'IPS: {k["isp"]}\n')
                        arquivo2.write(f'ASN: {k["asn"]}\n')
                        if 'location':
                            arquivo2.write(f'País: {k["location"]["country_name"]}\n')
                            arquivo2.write(f'Estado: {k["location"]["region_code"]}\n')
                            arquivo2.write(f'Cidade: {k["location"]["city"]}\n')
                            arquivo2.write(f'Dados:\n {k["data"]}\n\n')
            time.sleep(10)

        tempo = datetime.today().strftime('%d/%m/%Y - %H:%M:%S')
        arquivo2.write(f'########### FIM DO RELATÓRIO - {tempo} ###########')


def ip_censys(dados):
    hoje = datetime.today().strftime('%d/%m/%Y - %H:%M:%S')
    with open(f'enderecos_ip_{dados.split(" ")[2]}.txt', 'r') as arquivo, open(f'relatorio_censys_{dados.split(" ")[2]}.txt', 'a') as arquivo2:
        arquivo2.write(f'###########               CENSYS SEARCH                ###########\n')
        arquivo2.write(f'########### BUSCA POR ENDEREÇO IP - {hoje} ###########\n\n')
        ip = arquivo.readlines()
        for i in ip:
            result = api_censys.view(i.strip('\n'))
            arquivo2.write(f'\n\n=========================================\n')
            arquivo2.write(f'########## IP: {i} ##########\n')
            arquivo2.write(f'=========================================\n')

            try:
                arquivo2.write(f'País: {result["location"]["country"]}\n')
                arquivo2.write(f'Estado: {result["location"]["province"]}\n')
                arquivo2.write(f'Cidade: {result["location"]["city"]}\n')

                arquivo2.write(f'ASN: {result["autonomous_system"]["asn"]}\n')
                arquivo2.write(f'Nome ASN: {result["autonomous_system"]["name"]}\n')

                for h in result['services']:
                    arquivo2.write(f'\n>>>>> Serviço: {h["service_name"]}\n')
                    arquivo2.write(f'Porta: {h["port"]} - Protocolo: {h["transport_protocol"]}\n')

                    try:
                        if h['_decoded'] == 'http':
                            arquivo2.write(f'Banner: {h["banner"]}\n')

                        if h['_decoded'] == 's7':
                            arquivo2.write(f'Sistema: {h["s7"]["system"]}\n')
                            arquivo2.write(f'Módulo: {h["s7"]["module"]}\n')
                            arquivo2.write(f'Número Serial: {h["s7"]["serial_number"]}\n')
                            arquivo2.write(f'Tipo do Módulo: {h["s7"]["module_type"]}\n')
                            arquivo2.write(f'ID Módulo {h["s7"]["module_id"]}\n')
                            arquivo2.write(f'Tipo do Módulo: {h["s7"]["plant_id"]}\n')

                        if h['_decoded'] == 'modbus':
                            arquivo2.write(f'Fabricante: {h["modbus"]["mei_response"]["objects"]["vendor"]}\n')
                            arquivo2.write(f'Modelo: {h["modbus"]["mei_response"]["objects"]["product_code"]}\n')
                            arquivo2.write(f'Versão: {h["modbus"]["mei_response"]["objects"]["revision"]}\n')

                        if h['_decoded'] == 'banner_grab':
                            arquivo2.write(f'Fabricante: {h["parsed"]["eip"]["identity"]["vendor_name"]}\n')
                            arquivo2.write(f'Produto: {h["parsed"]["eip"]["identity"]["product_name"]}\n')
                            arquivo2.write(f'Versão: {h["parsed"]["eip"]["identity"]["revision"]}\n')
                            arquivo2.write(f'Banner: {h["banner"]}\n')
                    except:
                        pass

            except:
                pass
            time.sleep(10)

        tempo = datetime.today().strftime('%d/%m/%Y - %H:%M:%S')
        arquivo2.write(f'########### FIM DO RELATÓRIO - {tempo} ###########')



def main():
    print('##### BUSCA PLC #####')
    print('Para consultar digite: country:br port:{porta padrão do PLC} {fabricante do PLC}')
    print('Exemplro: country:br port:102 siemens')
    consulta = str(input('Digite a consulta: '))
    
    # print('--> Pesquisando no Shodan\n')
    pesquisa_shodan(consulta)
    
    # print('--> Fazendo Relatório do Shodan\n')
    ip_shodan(consulta)
    
    # print('--> Fazendo Relatório do Censys')
    ip_censys(consulta)



if __name__ == '__main__':
    main()