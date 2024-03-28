import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import policy_format
import terminal_fonts
from firewallbender.BackupConfigFiles import info_validation as infovalid

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def network_object(pool_info_tc):
    """
    Se estandariza la información para la creación de un objeto de tipo Addesses. Se retorna un objeto json con
    el formato para ser configurado a través de API Fortigate, asímismo la lista de nombres de cada uno de los
    objetos a configurar.
    :param pool_info_tc: lista de pool de ips con sus respectivos id, estos son ingresados de esta manera por fb_asker.
    :return: lista de objeto json (en formato) y lista de nombres.
    """
    pool_to_send, ip_pool_dict = list(), dict()
    name_list, object_json, name_dict, object_dict = list(), list(), dict(), dict()
    # Se recibe un array, esta al inicio podía ser de una dimensión o de dos, se envía ahora de dos dimensiones.
    if len(pool_info_tc.shape) == 1:
        ip_pool_dict['name'], ip_pool_dict['subnet'] = pool_info_tc[0], pool_info_tc[1]
        pool_to_send.append(ip_pool_dict)
    else:
        for info in pool_info_tc:
            ip_pool_dict['name'], ip_pool_dict['subnet'] = str(info[0]), str(info[1])
            pool_to_send.append(ip_pool_dict.copy())

    # name_dict contiene los nombres de los pools de IPs específicos para cada subred. Formato: Servicio-x.x.x.x/x,
    # entrega un diccionario de la forma {'name': 'Servicio-x.x.x.x/x'}
    # object_dict contiene los nombres de los pools de IPs específicos para cada subred y se respectiva subred.
    # entrega un diccionario de la forma {'name': 'Servicio-x.x.x.x/x', 'subnet': 'x.x.x.x/x'}
    for dictionary in pool_to_send:
        object_dict['name'] = f"{dictionary['name']}-{dictionary['subnet']}"
        name_dict['name'] = f"{dictionary['name']}-{dictionary['subnet']}"
        object_dict['subnet'] = dictionary['subnet']
        object_json.append(object_dict.copy())
        name_list.append(object_dict.copy())

    # Se guardan las variables en el formato deseado para ser enviadas a configurar al fortigate.
    object_json = json.dumps(object_json)
    return object_json, name_list


def check_status(response):
    """
    Valida las respuestas a los request de los métodos HTTP. Esta herramienta es utilizada para la presentación
    visual del resultado de una acción request.
    :param response: Respuesta de un request.status_code()
    :return: 1-> Exitoso (200), 0-> Problema de configuración/servidor Fortigate, 2-> Error usuario.
    """
    # Resultado favorable. Acción completada sin problemas.
    if str(response) == "200":
        print(terminal_fonts.bg_green(" ✔ "))
        print("\n")
        return 1
    # El equipo no puede culminar la acción porque los valores enviados son imposibles de configurar,
    # generalmente por información duplicada.
    elif str(response) == "500":
        print(terminal_fonts.bg_fail(" X "))
        print(terminal_fonts.fail(f'Error: {response}'))
        print("\n")
        return 0
    # Response: 400, etc. Validar.
    else:
        print(terminal_fonts.bg_fail(" ? "))
        print(terminal_fonts.fail(f'Error: {response}'))
        print("\n")
        return 2


class fortigate_connection:
    """
    Herramienta que permite la creación de un objeto conectado a un equipo Fortigate, el cual puede realizar
    varias configuraciones y validaciones.
    """
    def __init__(self, fw_location, fw_ip, fw_token, pool_tc, id_tc, src_int_tc, dst_int_tc, vlan_tc, comment_tc):
        """
        :param fw_location: Localidad en el listado disponible: Colombia, Ecuador, Guatemala y Panamá.
        :param fw_ip: IP de ingreso al Firewall de la localidad escogida
        :param fw_token: Llave para ingreso a firewall por medio de API Rest.
        :param pool_tc: Lista de pool de IPs junto con el id.
        :param id_tc: ID del servicio a configurar.
        :param src_int_tc: Interfaz fuente correspondiente al equipo de la localidad escogida.
        :param dst_int_tc: Interfaz destinatoria correspondiente al equipo de la localidad escogida.
        :param vlan_tc: Vlan del servicio a configurar
        :param comment_tc: Comentario a guardar por cada servicio configurado, generalmente hace referencia
        a la dirección física en el cual se encuentra configurado el servicio.
        """
        self.fw_location = fw_location
        self.fw_ip = fw_ip
        self.fw_token = fw_token
        self.pool_tc = pool_tc
        self.id_tc = id_tc
        self.src_int_tc = src_int_tc
        self.dst_int_tc = dst_int_tc
        self.vlan_tc = vlan_tc
        self.comment_tc = comment_tc

    def get_fw_location(self):
        return self.fw_location

    def get_fw_ip(self):
        return self.fw_ip

    def get_fw_token(self):
        return self.fw_token

    def get_pool_tc(self):
        return self.pool_tc

    def get_id_tc(self):
        return self.id_tc

    def get_src_int_tc(self):
        return self.src_int_tc

    def get_dst_int_tc(self):
        return self.dst_int_tc

    def get_vlan_tc(self):
        return self.vlan_tc

    def get_comment_tc(self):
        return self.comment_tc

    def create_network_object(self):
        """
        Creación de un objeto de red. Para esto se utiliza la función de formato de objeto de red: network_object.
        :return: Nombres de los objetos de red configurados, el segundo valor de la función network_object.
        """
        info_to_config = network_object(self.get_pool_tc())
        pool_to_config, object_config = info_to_config[0], info_to_config[1]

        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/firewall/address?access_token={self.fw_token}'
        url_object, url_headers = {}, {}
        url_information = requests.post(url, headers=url_headers, data=pool_to_config, verify=False)
        check_status(url_information.status_code)

        return object_config

    def create_network_interface(self):
        """
        Creación de las interfaces de red en el bloque de Network - Interfaces.
        :return: En el caso de que haya realizado la configuración retorna True, caso contrario realiza la
        búsqueda de una interfaz que esté duplicada en el equipo.
        """
        policy_to_config = json.dumps(policy_format.rni_interface_format(self.get_id_tc(), self.get_pool_tc(),
                                                                         self.get_vlan_tc(), self.comment_tc))

        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/system/interface/?access_token={self.fw_token}'
        url_object, url_headers = {}, {}
        url_information = requests.post(url, headers=url_headers, data=policy_to_config, verify=False)
        if check_status(url_information.status_code) != 1:
            return self.find_existing_interface_info()
        else:
            return True

    def create_sg_policy(self):
        object_config = self.create_network_object()
        policy_name = self.get_id_tc()
        sg_policy = policy_format.sg_policy_format(policy_name, object_config, self.get_src_int_tc(),
                                                   self.get_dst_int_tc())
        policy_to_config = json.dumps(sg_policy)

        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/firewall/policy/?vdom=root&access_token={self.fw_token}'
        url_object, url_headers = {}, {}
        url_information = requests.post(url, headers=url_headers, data=policy_to_config, verify=False)
        if check_status(url_information.status_code) != 1:
            print("No se ha podido configurar la política, validar.")
        else:
            id_policy = self.get_specific_id(f"sg-demo-{policy_name}")
            reference_id = self.move_policy()
            url = f'https://{self.get_fw_ip()}/api/v2/cmdb/firewall/policy/{id_policy}?vdom=root&' \
                  f'action=move&after={reference_id}&access_token={self.fw_token}'
            requests.put(url, headers=url_headers, verify=False)
            pass

    def create_rni_policy(self):
        rni_policy = policy_format.rni_policy_format(self.get_id_tc())
        policy_to_config = json.dumps(rni_policy)

        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/firewall/policy/?vdom=root&access_token={self.fw_token}'
        url_object, url_headers = {}, {}
        url_information = requests.post(url, headers=url_headers, data=policy_to_config, verify=False)
        if check_status(url_information.status_code) != 1:
            print(url_information.status_code)
            return self.find_existing_policy_info()
        else:
            return True

    def get_file_config(self):
        url = f'https://{self.get_fw_ip()}/api/v2/monitor/system/config/backup?scope=global&' \
              f'access_token={self.get_fw_token()}'
        url_object, url_headers = {}, {}
        try:
            url_information = requests.get(url, headers=url_headers, verify=False)
            if str(url_information.status_code) == "200":
                return url_information
            else:
                print(url_information.status_code)
                return None
        except TimeoutError:
            print("No se llega")
            return None
        except requests.exceptions.ConnectTimeout:
            print("Timeout Request")
            return None
        except requests.exceptions.ConnectionError:
            print("Connection Error")
            return None

    def get_specific_id(self, id_name):
        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/firewall/policy/?filter=name=={id_name}&' \
              f'vdom=root&access_token={self.fw_token}&format=policyid|name|action'
        url_object, url_headers = {}, {}
        url_information = requests.get(url, headers=url_headers, verify=False)
        id_policy_reference = self.search_first_sg_policy(url_information.json()["results"])
        return id_policy_reference

    def move_policy(self):
        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/firewall/policy/?vdom=root&access_token={self.fw_token}' \
              f'&format=policyid|name|action'
        url_object, url_headers = {}, {}
        url_information = requests.get(url, headers=url_headers, verify=False)
        id_policy_reference = self.search_first_sg_policy(url_information.json()["results"])
        return id_policy_reference

    def search_first_sg_policy(self, json_information_policy):
        for policy in json_information_policy:
            if policy["name"].startswith("sg-demo-"):
                url = f'https://{self.get_fw_ip()}/api/v2/cmdb/firewall/policy/{policy["policyid"]}' \
                      f'?vdom=root&access_token={self.fw_token}'
                url_object, url_headers = {}, {}
                requests.get(url, headers=url_headers, verify=False)
                return policy["policyid"]
            else:
                pass

    def find_existing_interface_info(self):
        filter_list = {
            "name": f"{self.get_id_tc()[:15]}",
            "vlanid": f"{self.get_vlan_tc()}",
            "ip": f"{infovalid.pool_prefix2netmask(self.get_pool_tc())}",
            "alias": f"{self.id_tc}"
        }
        existing_parameter, wrong_parameter = dict(), str()
        for parameter in filter_list.keys():
            url = f'https://{self.get_fw_ip()}/api/v2/cmdb/system/interface/?filter={parameter}==' \
                  f'{filter_list[parameter]}&vdom=root&access_token={self.fw_token}&format=name|vlanid|ip|alias'
            url_object, url_headers = {}, {}
            url_information = requests.get(url, headers=url_headers, verify=False)
            if len(url_information.json()["results"]) == 1:
                existing_parameter[parameter] = url_information.json()["results"][0][parameter]
            elif (filter_list[parameter] is None) or (filter_list[parameter] is False):
                wrong_parameter[parameter] = self.get_pool_tc()
            else:
                pass
        return existing_parameter, wrong_parameter

    def find_existing_interface(self):

        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/system/interface&vdom=root&access_token=' \
              f'{self.fw_token}&format=name|vlanid|ip|alias'
        url_object, url_headers = {}, {}
        url_information = requests.get(url, headers=url_headers, verify=False)

        return url_information.text

    def find_existing_policy_info(self):
        existing_parameter = dict()
        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/firewall/policy/?filter=name==' \
              f'{self.get_id_tc()}&vdom=root&access_token={self.fw_token}&format=policyid|name|action'
        url_object, url_headers = {}, {}
        url_information = requests.get(url, headers=url_headers, verify=False)
        try:
            if len(url_information.json()["results"]) == 1:
                existing_parameter["name"] = url_information.json()["results"][0]["name"]
            else:
                pass
        except json.decoder.JSONDecodeError:
            check_status(url_information.status_code)
        return existing_parameter

    def test_api(self):
        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/firewall/policy/?vdom=root&access_token={self.fw_token}' \
              f'&format=policyid|name|action'
        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/system/interface/?vdom=root&access_token={self.fw_token}'
        url = f'https://{self.get_fw_ip()}/api/v2/cmdb/firewall/policy/?vdom=root&access_token={self.fw_token}'
        url_object, url_headers = {}, {}
        try:
            url_information = requests.get(url, headers=url_headers, verify=False)
            print(url_information.text)
        except TimeoutError:
            print("No se llega")
        except requests.exceptions.ConnectTimeout:
            print("Timeout Request")


