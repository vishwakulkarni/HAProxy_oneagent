"""
OneAgent HAProxy plugin
=======================

Gathers HAProxy stats served by the load balancer as a csv. The full description of stats is
available at https://cbonte.github.io/haproxy-dconv/configuration-1.5.html#9

Configuration includes:

 * credentials, if stats are guarded by HTTP basic-auth.
 * url to stats page - ";csv" will be automatically appended if missing. If url is absolute, it will
   remain so, if it is relative, it will be joined with "http://localhost" prefix
 * if configuration fields remain empty, plugin tries to gather metrics from socket(detected from HAProxy conf file)

An example HAProxy stats csv::

    # pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,
    haproxy-backend,server_behind_haproxy,0,0,0,1,,27,8180,41254,,0,,0,0,0,0,no check,1,1,0,,,,,,1,1,1,,27,,2,0,,2,,,,0,8,0,19,3,0,0,,,,0,0,,,,,351293,,,0,1,2,13,
    haproxy-backend,BACKEND,0,0,0,1,100,21962,5579929,25660881,0,0,,0,0,0,0,UP,1,1,0,,0,2863759,0,,1,1,0,,27,,1,0,,2,,,,0,21940,0,22,0,0,,,,,0,0,0,0,0,0,78967,,,0,0,0,1,
    haproxy-frontend,FRONTEND,,,1,3,1000,23283,5885422,27269302,0,0,3,,,,,OPEN,,,,,,,,,1,2,0,,,,0,1,0,3,,,,0,23257,0,25,0,0,,1,3,23283,,,0,0,0,0,,,,,,,,
    stats,FRONTEND,,,0,0,2000,0,0,0,0,0,0,,,,,OPEN,,,,,,,,,1,3,0,,,,0,0,0,0,,,,0,0,0,0,0,0,,0,0,0,,,0,0,0,0,,,,,,,,

The measurements are gathered following few rules:

 * each measurement is associated with service dimension(except of "idle" measurement). This allows sending multiple values of the
   same metric (for example reqest rate) under the same key, just changing the dimension.
 * idle measurement is aggregated from all active processes.
 * rows where svname=BACKEND are ignored. In the example above "haproxy-backend,BACKEND" would be ignored
 * rows where svname=FRONTEND are associated with service dimension set to the value of pxname.
   In the example above, this would apply to "haproxy-frontend,FRONTEND" and "stats,FRONTEND" rows
 * measurement keys specified in json mostly mirror the ones specified in HAProxy docs, with additional
   `be_` or `fe_` prefix to indicate whether they apply to frontends or backends

Limitations:

 * HAProxy needs to be configured to serve statistics on a particular url/socket, which might not be enabled by default.
 * Multiple HAProxy worker processes running on the same configuration is now supported. It is suggested to use 
   socket mode in this case.
 * One instance of the plugin is created for each detected HAProxy process group instance. However
   current ruxit agent implementations merges all HAProxy processes into one process group, which means
   this effectively is a singleton plugin.
 * SSL certificate verification is disabled.

"""
import requests
import requests.exceptions
import socket
import csv
import urllib.parse
import logging
from ruxit.api.data import PluginMeasurement
from ruxit.api.base_plugin import BasePlugin
from ruxit.api.exceptions import AuthException, ConfigException

logger = logging.getLogger(__name__)

class HaProxyPlugin(BasePlugin):
    """
    HAProxy plugin class. This plugin is stateful, however, the state is limited to some
    processing of received configuration, and no resources are acquired.
    """

    _HELP_URL = "{HAPROXY_REF_URL}"
    _HELP_MORE_INFO = 'For more details visit ' + _HELP_URL

    _DEFAULT_TIMEOUT_SECONDS = 2
    _ABSOLUTE_METRICS = {'fe_req_rate', 'fe_scur', 'be_scur', 'scur', 'be_qcur', 'fe_susage', 'be_susage', 'be_rtime', 'status', 'idle'}
    _NO_PREFIX_METRICS = {'hrsp_4xx', 'hrsp_5xx', 'scur', 'bin', 'bout'}


    def initializeSockets(self, kwargs):
        self.socketGain = True
        
        entity = kwargs["associated_entity"] 
        entityCount = 1

        confDir = '/etc/haproxy/haproxy.cfg'
        for procInfo in entity.processes:
            if 'CmdLine' in procInfo.properties:
                snapCmdLine = procInfo.properties['CmdLine'].split(' ')
                if '-f' in snapCmdLine:
                    confDir = snapCmdLine[snapCmdLine.index("-f") + 1]
                    break

        self.url = []
        try:
            confFile = open(confDir, "r")
        except IOError:
            raise ConfigException('Cannot open HAProxy configuration file. Please check file permissions. ' + self._HELP_MORE_INFO)
        else:
            bindErr = False
            with confFile:
                for line in confFile:
                    line = line.partition('#')[0]
                    line = line.strip()
                    if "stats socket" in line:
                        if not "process" in line:
                            bindErr = True
                        tmp = line.split(' ')
                        sockAddr = tmp[tmp.index("socket") + 1]
                        self.url.append(sockAddr)
                        
                        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        try:
                            sock.connect(sockAddr)
                            sock.close()
                        except OSError as msg:
                            raise ConfigException('Cannot connect to the stats socket. Please check file permissions. ' + self._HELP_MORE_INFO)
                    elif "nbproc" in line:
                        tmp = line.split(' ')
                        try:
                            entityCount = int(tmp[tmp.index("nbproc") + 1])
                        except:
                            raise ConfigException('Cannot define number of processes - HAProxy configuration error. Please check HAProxy configuration file. ' + self._HELP_MORE_INFO)
        if entityCount != len(self.url):
            raise ConfigException('Number of stats sockets and processes differ. There should be one socket for each HAProxy process. ' + self._HELP_MORE_INFO)
        if bindErr and entityCount > 1:
            raise ConfigException('Socket is not bound to any process. Please check HAProxy configuration file. ' + self._HELP_MORE_INFO)

    def initialize(self, **kwargs):
        """
        Plugin initialization is limited to parsing configuration in order to construct
        url and auth parameters for later HTTP requests.
        When configuration is empty(removed by user) plugin tries to gain metrics by socket
        """
        self.socketGain = False
        
        #config = kwargs['config']
        self.url = self.get_connection_url()
        self.timeout = self._DEFAULT_TIMEOUT_SECONDS

        self.auth = None
        self.auth = self.get_user_credentials()

        self.verify = False
        print("Initializing")
        self.initializeSockets(kwargs)
    def get_user_credentials():
        return ('admin','admin')
    def get_connection_url():
        return 'http://localhost:9000/haproxy_stats'

    def getResponseFromHttp(self, url):
        try:
            response = requests.get(
                url,
                auth=self.auth,
                verify=self.verify,
                timeout=self.timeout)
        except (requests.exceptions.MissingSchema,
                requests.exceptions.InvalidSchema,
                requests.exceptions.InvalidURL) as ex:
            raise ConfigException('URL: "%s" does not appear to be valid' % url) from ex
        except requests.exceptions.ConnectTimeout as ex:
            raise ConfigException('Timeout on connecting with "%s"' % url) from ex
        except requests.exceptions.RequestException as ex:
            raise ConfigException('Unable to connect to "%s"' % url) from ex
        if response.status_code == requests.codes.UNAUTHORIZED:
            raise AuthException(response)
        return response
        
        
    def getResponseFromSocket(self, url, command):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
        try:
            sock.connect(url)
            message = command
            sock.send(str.encode(message))
            file_handle = sock.makefile()
            response = file_handle.read()
            sock.close()
        except OSError as msg:
            raise ConfigException('Cannot connect to the stats socket. Please check file permissions. ' + self._HELP_MORE_INFO)
        return response
    

    def readSocket(self, url):
        response = self.getResponseFromSocket(url, 'show stat\n')

        stats_csv_rows = [row for row in csv.DictReader(response.splitlines())]
        if len(stats_csv_rows) == 0:
            raise ConfigException('Content from "%s" does not appear to be in haproxy stats format' % url)
        return stats_csv_rows
    
    
    def readHttp(self, url):
        print("reading from url")
        if not url.endswith(';csv'):
            url += ";csv"
        
        response = self.getResponseFromHttp(url)
    
        stats_csv_rows = [row for row in csv.DictReader(response.content.decode().splitlines())]
        if len(stats_csv_rows) == 0:
            raise ConfigException('Content from "%s" does not appear to be in haproxy stats format' % url)
        print(stats_csv_rows)
        return stats_csv_rows
    
    
    def getIdleFromSocket(self, url):
        response = self.getResponseFromSocket(url, 'show info\n')   
                
        stats_rows = response.splitlines()
        for row in stats_rows:
            if 'Idle_pct:' in row:
                return row.split(' ')[1]
    
            
    def getIdleFromHttp(self, url):
        if url.endswith(';csv'):
            url = url[:-4]
    
        response = self.getResponseFromHttp(url)
        
        html_lines = response.content.decode().splitlines()
        for row in html_lines:
            if 'idle =' in row:
                return row.split('idle =')[1].split('%')[0].strip()
    
    
    def query(self, **kwargs):
        """
        Tries to gather as much data as possible without raising errors -
        as long as a csv is received with enough information to extract proxy and server names,
        but some metrics missing - no errors are raised. This is to prevent unnecessary
        problems when different HAProxy versions provide different sets of metrics.

        Raises:
            ruxit.api.exceptions.AuthException: HAProxy responded with 401
            ruxit.api.exceptions.ConfigException: connection and data parsing errors
        """
    
        measurementList = {}
        measurementList['no_dim'] = {}
    
        for url in self.url:
            if(self.socketGain):
                stats_csv_rows = self.readSocket(url)               
                
                if not ('idle' in measurementList['no_dim']):
                    measurementList['no_dim']['idle'] = []
                measurementList['no_dim']['idle'].append(
                    self.getIdleFromSocket(url)
                )
                
            else:
                stats_csv_rows = self.readHttp(url)
                
                if not ('idle' in measurementList['no_dim']):
                    measurementList['no_dim']['idle'] = []
                measurementList['no_dim']['idle'].append(
                    self.getIdleFromHttp(url)
                )
            
            for row in stats_csv_rows:
                try:
                    pxname = row['# pxname']
                    svname = row['svname']
                    dimensionName = pxname
        
                    if svname == 'FRONTEND':
                        metric_prefix = "fe_"
                        prefix_metrics = {'ereq', 'scur', 'susage', 'req_rate', 'bin', 'bout'}
                    elif svname == 'BACKEND':
                        continue
                    else:
                        metric_prefix = 'be_'
                        prefix_metrics = {'econ', 'eresp', 'qcur', 'scur', 'susage', 'bin', 'bout', 'rtime'}
                except KeyError as ex:
                    raise ConfigException('Content from "%s" does not appear to be in haproxy stats format' % url) from ex
                
                all_metrics = prefix_metrics.union(self._NO_PREFIX_METRICS)
                    
                if not (dimensionName in measurementList):
                        measurementList[dimensionName] = {}
    
                for metric in all_metrics:
                    if metric in row and metric in prefix_metrics:
                        metric_value = row[metric]
                        if metric_value == '' or metric_value == None:
                            continue
                        metric_json_name = metric_prefix + metric
                        if not (metric_json_name in measurementList[dimensionName]):
                            measurementList[dimensionName][metric_json_name] = []
                        measurementList[dimensionName][metric_json_name].append(
                            metric_value
                        )
                    if metric in row and metric in self._NO_PREFIX_METRICS:
                        metric_value = row[metric]
                        if metric_value == '' or metric_value == None:
                            continue
                        metric_json_name = metric
                        if not (metric_json_name in measurementList[dimensionName]):
                            measurementList[dimensionName][metric_json_name] = []
                        measurementList[dimensionName][metric_json_name].append(
                            metric_value
                        )
                    elif metric == 'susage':
                        try:
                            scur = row['scur']
                            slim = row['slim']
                            if scur == '' or slim == '' or scur == None or slim == None:
                                continue
                            metric_json_name = metric_prefix + metric
                            if not (metric_json_name in measurementList[dimensionName]):
                                measurementList[dimensionName][metric_json_name] = []
                            measurementList[dimensionName][metric_json_name].append(
                                (float(scur)/float(slim))*100
                            )
                        except KeyError as ex:
                            raise ConfigException('Content from "%s" does not appear to be in haproxy stats format' % url) from ex

        for dimension, metricsList in measurementList.items():
            dimensions = {'service': dimension}
            for metricKey, metricValues in metricsList.items():
                aggregatedValue = 0
                for value in metricValues:
                    aggregatedValue += float(value)
                if ("susage" in metricKey):
                    self.results_builder.add_absolute_result(
                        PluginMeasurement(dimensions=dimensions, key=metricKey, value=aggregatedValue/len(metricValues))
                    )
                elif ("idle" in metricKey):
                    self.results_builder.add_absolute_result(
                        PluginMeasurement(key=metricKey, value=aggregatedValue/len(metricValues))
                    )
                elif metricKey in self._ABSOLUTE_METRICS:
                    self.results_builder.add_absolute_result(
                        PluginMeasurement(dimensions=dimensions, key=metricKey, value=int(aggregatedValue))
                    )
                else:
                    self.results_builder.add_relative_result(
                        PluginMeasurement(dimensions=dimensions, key=metricKey, value=int(aggregatedValue))
                    )
