import os, sys
import datetime
import time
import md5
import hmac
import base64
import hashlib
import requests
import abc
from argparse import ArgumentParser
from lxml import etree
from contextlib import contextmanager

requests.packages.urllib3.disable_warnings()

#
# Pulled in from python-ds3sdk
#

# NOTE Change to False to turn off forced bucket deletion safety.
SAFETY = True

# Job priorities.
URGENT = 'URGENT'
HIGH   = 'HIGH'
NORMAL = 'NORMAL'
LOW    = 'LOW'

# GET job orderings.
IN_ORDER = 'IN_ORDER'
NO_ORDER = 'NO_ORDER'

# PUT job optimizations.
OPTIMIZE_DISK = 'CAPACITY'
OPTIMIZE_PERF = 'PERFORMANCE'

try: # Python 2.x
    import urlparse as parser
except ImportError: # Python 3.x
    import urllib.parse as parser

class DS3Exception(Exception):
    '''
    Base DS3 Exception Class
    '''
    pass

class DS3NoResultFound(DS3Exception):
    '''
    No results found in query.
    '''
    pass

class DS3MultipleResultsFound(DS3Exception):
    '''
    Multiple results found in query.
    '''
    pass

class Query(object):
    '''
    DS3 Query Base Class
    '''
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __call__(self, **params):
        '''
        Returns a new instance of the Query, with parameters applied.
        '''
        raise NotImplementedError('derived class must implement')

    @abc.abstractmethod
    def __iter__(self):
        '''
        Performs a query based on the given parameters.
        '''
        raise NotImplementedError('derived class must implement')

    def __len__(self):
        '''
        Returns the number of items returned by the query.
        '''
        return sum(1 for _ in iter(self))

    def __contains__(self, item):
        '''
        Checks that an element exists in the query.
        '''
        return item in iter(self)

    def one(self):
        '''
        Returns the first element of the buckets list.
        Raises a DS3NoResultFound if no elements were found.
        Raises a DS3MultipleResultsFound if more than one element was found.
        '''
        it = iter(self)
        
        try: first = it.next()
        except StopIteration: raise DS3NoResultFound()
        
        try: it.next()
        except StopIteration: pass
        else: raise DS3MultipleResultsFound()
        
        return first

    def first(self):
        '''
        Returns the first element of the buckets list.
        Raises a DS3NoResultFound if no elements were found.
        '''
        it = iter(self)
        
        try: first = it.next()
        except StopIteration: raise DS3NoResultFound()
        
        return first

    def scalar(self):
        '''
        Returns the first element of the buckets list.
        Raises a DS3MultipleResultsFound if more than one element was found.
        '''
        it = iter(self)
        
        try: first = it.next()
        except StopIteration: first = None
        
        try: it.next()
        except StopIteration: pass
        else: raise DS3MultipleResultsFound()
        
        return first

class DS3Auth(requests.auth.AuthBase):
    '''
    DS3 HMAC Authentication
    '''
    def __init__(self, access_key, secret_key, **kwargs):
        self.access_key = access_key
        self.secret_key = secret_key

    def __call__(self, r):
        r.headers['Date'] = r.headers.get('Date', time.asctime(time.gmtime()))
        r.headers['Authorization'] = 'AWS {access_key}:{signed_key}'.format(
            access_key=self.access_key,
            signed_key=self.sign(self.canonicalize(
                r.method,
                parser.urlparse(r.url).path,
                **r.headers
            ))
        )
        
        return r

    def sign(self, msg):
        return base64.encodestring(
            hmac.new(
                self.secret_key.encode('utf-8'),
                msg.encode('utf-8'),
                hashlib.sha1,
            ).digest(),
        ).decode('utf-8').strip('\n')

    def canonicalize(self, verb, resource, **headers):
        return '\n'.join([
            str(verb),
            str(headers.pop('Content-MD5','')),
            str(headers.pop('Content-Type','')),
            str(headers.pop('Date','')),
            '', # TODO include headers properly
        ]) + str(resource)

class Bucket(object):
    '''
    DS3 Bucket
    '''
    RESOURCE = '/_rest_/bucket/'

    def __init__(self, client, name=None, id=None, xml=None):
        self.client = client

        # Verify that we have enough to specify the bucket.
        if not any([
            id,
            name,
            xml is not None,
        ]): raise ValueError('must specify id, name, or xml')
        
        # Store these as private members for XML retrieval.
        self.id = id
        self.name = name
        
        self._xml = xml
        if isinstance(xml, basestring):
            self._xml = etree.fromstring(xml)

    @classmethod
    def fromxml(cls, client, xml):
        bucket_id = xml.find('./Id').text
        bucket_name = xml.find('./Name').text
        
        return cls(client, name=bucket_name, id=bucket_id, xml=xml)

    def update(self):
        '''
        Updates the bucket to use the latest server XML.
        '''
        params = {
            'id': self.id,
            'name': self.name,
        }
        
        with self.client.get(self.RESOURCE, params=params) as res:
            
            # Check for positive response and parse XML body.
            res.raise_for_status()
            root = etree.fromstring(res.text)
        
        # Check that we found exactly one bucket.
        found = len(list(root.findall('./Bucket')))
        if found is 0:
            raise DS3NoResultFound('bucket could not be found')
        if found is not 1:
            raise DS3MultipleResultsFound('multiple buckets found')
        
        self._xml = root.find('./Bucket')
        
        xml_bucket_id = self.xml.find('./Id').text
        if self.id and xml_bucket_id != self.id:
            # TODO change to a DS3 error
            raise ValueError('bucket id mismatch with server xml')
        self.id = xml_bucket_id
        
        xml_bucket_name = self.xml.find('./Name').text
        if self.name and xml_bucket_name != self.name:
            # TODO change to a DS3 error
            raise ValueError('bucket name mismatch with server xml')
        self.name = xml_bucket_name

    def __str__(self):
        return str(self.name)

    def __eq__(self, other):
        try: return self.id == other.id
        except: return False

    def delete(self, force=False):
        '''
        Delete the bucket.
        '''
        params = {}
        params['force'] = force and not SAFETY or None
        
        resource = urlparse.urljoin(self.RESOURCE, str(self.name))
        with self.client.delete(resource, params=params) as res:
            res.raise_for_status()

    @property
    def xml(self):
        if self._xml is None:
            self.update()
        return self._xml

    @property
    def optimization(self):
        return self.xml.find('./DefaultWriteOptimization').text

    # TODO define other getters for the rest of the response xml
    # ...

    @property
    def keys(self):
        return Keys(self.client, bucket_id=self.id)


class Buckets(Query):
    '''
    DS3 Buckets View

    Provides a bucket-centric view of the client.
    '''

    RESOURCE = '/_rest_/bucket/'

    def __init__(self, client, **params):
        self.client = client
        self.params = params

    def __call__(self, name=None, **params):
        p = dict(self.params)
        p.update(params)
        p['name'] = name
        return Buckets(self.client, **p)

    def __iter__(self):
        with self.client.get(self.RESOURCE, params=self.params) as res:
            res.raise_for_status()
            root = etree.fromstring(res.text)
            for bucket in root.findall('./Bucket'):
                yield Bucket.fromxml(self.client, bucket)

    def create(self, name, **params):
        '''
        Create a new bucket.
        '''
        # TODO specify parameters?
        params['name'] = str(name)
        
        with self.client.post(self.RESOURCE, params=params) as res:
            res.raise_for_status()
            return Bucket(self.client, name)

    def delete(self, name, force=False, **params):
        '''
        Delete a bucket.
        '''
        params['force'] = force and not SAFETY or None
        
        resource = urlparse.urljoin(self.RESOURCE, str(name))
        with self.client.delete(resource, params=params) as res:
            res.raise_for_status()

class Key(object):
    '''
    DS3 Key
    '''
    RESOURCE = '/_rest_/object/'

    def __init__(self, client, name=None, bucket_name=None, bucket_id=None, id=None, xml=None):
        self.client = client
        
        # Verify that we have enough to specify the key.
        if not any([
            id,
            name and (bucket_name or bucket_id),
            xml is not None,
        ]): raise ValueError('must specify id, name and bucket, or xml')
        
        # Store these as private members for XML retrieval.
        self.id = id
        self.name = name
        self.bucket_id = bucket_id
        self.bucket_name = bucket_name
        
        self._xml = xml
        if isinstance(xml, basestring):
            self._xml = etree.fromstring(xml)

    @classmethod
    def fromxml(cls, client, xml):
        key_id = xml.find('./Id').text
        key_name = xml.find('./Name').text
        bucket_id = xml.find('./BucketId').text
        
        return cls(client, name=key_name, id=key_id, bucket_id=bucket_id, xml=xml)

    def update(self):
        '''
        Updates the key to use the latest server XML.
        '''
        params = {
            'id': self.id,
            'name': self.name,
            'bucket_id': self.bucket_id,
        }
        
        with self.client.get(self.RESOURCE, params=params) as res:
            
            # Check for positive response and parse XML body.
            res.raise_for_status()
            root = etree.fromstring(res.text)
        
        # Check that we found exactly one key.
        found = len(list(root.findall('./S3Object')))
        if found is 0:
            raise DS3NoResultFound('key could not be found')
        if found is not 1:
            raise DS3MultipleResultsFound('multiple keys found')
        
        self._xml = root.find('./S3Object')
        
        xml_key_id = self.xml.find('./Id').text
        if self.id and xml_key_id != self.id:
            # TODO change to a DS3 error
            raise ValueError('key id mismatch with server xml')
        self.id = xml_key_id
        
        xml_key_name = self.xml.find('./Name').text
        if self.name and xml_key_name != self.name:
            # TODO change to a DS3 error
            raise ValueError('key name mismatch with server xml')
        self.name = xml_key_name
        
        xml_bucket_name = self.xml.find('./BucketId').text
        if self.bucket_name and xml_bucket_name != self.bucket_name:
            # TODO change to a DS3 error
            raise ValueError('bucket name mismatch with server xml')
        self.bucketid = xml_bucket_name

    def __str__(self):
        return str(self.name)

    def __eq__(self, other):
        '''
        Compare two keys to see if they represent the same key.
        NOTE this compares key ids, NOT local representation
        '''
        try: return self.id == other.id
        except: return False

    def get(self, job=None, offset=0, chunk_size=8192):
        '''
        GET data from the key as an iterable of byte chunks.
        '''
        bucket = self.bucket
        bucket.update()
        
        resource = '/{bucket}/{name}'.format(
            bucket=bucket,
            name=self.name,
        )
        
        params = {
            'job': job,
            'offset': offset,
        }
        
        with self.client.get(resource, params=params) as res:
            res.raise_for_status()
            for chunk in res.iter_content(chunk_size=chunk_size):
                yield chunk

    def put(self, itt, job=None, offset=0):
        '''
        PUT data from an iterable to the key.
        '''
        bucket = self.bucket
        bucket.update()
        
        resource = '/{bucket}/{name}'.format(
            bucket=bucket,
            name=self.name,
        )
        
        params = {
            'job': job,
            'offset': offset,
        }
        
        with self.client.put(resource, data=itt, params=params) as res:
            res.raise_for_status()

    def get_contents_to_string(self, job=None, offset=None):
        '''
        GET data from a key to string
        '''
        bucket = self.bucket
        bucket.update()
        
        resource = '/{bucket}/{name}'.format(
            bucket=bucket,
            name=self.name,
        )
        
        params = {
            'job': job,
            'offset': offset,
        }
        
        with self.client.get(resource, params=params) as res:
            res.raise_for_status()
            return res.text

    def get_contents_to_file(self, ofs, job=None, offset=None, chunk_size=8192):
        '''
        GET data from a key to a file-like object.
        Writes bytes to the current position of the file-like object.
        '''
        bucket = self.bucket
        bucket.update()
        
        resource = '/{bucket}/{name}'.format(
            bucket=bucket,
            name=self.name,
        )
        params = {
            'job': job,
            'offset': offset,
        }
           
        with self.client.get(resource, params=params) as res:
            res.raise_for_status()
            for chunk in res.iter_content(chunk_size=chunk_size):
                ofs.write(chunk)

    def delete(self):
        '''
        Delete the key.
        '''
        bucket = self.bucket
        bucket.update()
        
        resource = '/{bucket}/{key}'.format(
            bucket=bucket,
            key=str(self.name),
        )
        with self.client.delete(resource) as res:
            res.raise_for_status()

    @property
    def xml(self):
        if self._xml is None:
            self.update()
        return self._xml

    @property
    def creation_date(self):
        self._creation_date = self.xml.find('.CreationDate').text
        return self._creation_date


    @property
    def bucket(self):
        return Bucket(self.client,
            id=self.bucket_id,
            name=self.bucket_name,
        )

    @property
    def type(self):
        return self.xml.find('./Type').text

    @property
    def version(self):
        return self.xml.find('./Version').text


class Keys(Query):
    '''
    DS3 Keys View
    
    Provides a key-centric view of the client.
    '''
    RESOURCE = '/_rest_/object/'

    def __init__(self, client, **params):
        self.client = client
        self.params = params

    def __call__(self, name=None, **params):
        p = dict(self.params)
        p.update(params)
        p['name'] = name
        return Keys(self.client, **p)

    def __iter__(self):
        '''
        Generator for keys matching specified parameters.
        '''
        with self.client.get(self.RESOURCE, params=self.params) as res:
            res.raise_for_status()
            root = etree.fromstring(res.text)
            for key in root.findall('./S3Object'):
                yield Key.fromxml(self.client, key)

    def create(self, fd, key, bucket=None):
        '''
        Create a new key and associated job.
        '''
        resource = '/{bucket}/{key}'.format(
            bucket=bucket or self.params['bucket'],
            key=key,
        )
        
        with self.client.put(resource, data=fd) as res:
            res.raise_for_status()
            
            return Key(self.client, name=key, bucket_name=bucket)

    def delete(self, bucket, key):
        '''
        Delete a key.
        '''
        resource = '/{bucket}/{key}'.format(
            bucket=str(bucket),
            key=str(key),
        )
        with self.client.delete(resource) as res:
            res.raise_for_status()



class Job(object):
    '''
    DS3 Job
    '''
    RESOURCE = '/_rest_/job/'

    def __init__(self, client, id=None, xml=None):
        self.client = client
        
        # Verify that we have enough to specify the job.
        if not any([
            id,
            xml is not None,
        ]): raise ValueError('must specify id, or xml')
        
        self.id = id
        
        self._xml = xml
        if isinstance(xml, basestring):
            self._xml = etree.fromstring(xml)

    @classmethod
    def fromxml(cls, client, xml):
        job_id = xml.attrib['JobId']
        
        return cls(client, id=job_id, xml=xml)

    def update(self):
        '''
        Updates the job to use the latest server XML.
        '''
        # TODO if job filtering is updated, change all this
        
        resource = urlparse.urljoin(self.RESOURCE, str(self.id))
        
        with self.client.get(resource) as res:
            
            # Check for positive response and parse XML body.
            res.raise_for_status()
            root = etree.fromstring(res.text)
        
        self._xml = root
        
        xml_job_id = self.xml.attrib['JobId']
        if self.id and xml_job_id != self.id:
            # TODO change to a DS3 error
            raise ValueError('job id mismatch with server xml')
        self.id = xml_job_id

    def __str__(self):
        return str(self.id)

    def __eq__(self, other):
        try: return self.id == other.id
        except: return False

    def delete(self):
        '''
        Delete the job.
        '''
        resource = urlparse.urljoin(self.RESOURCE, str(self.id))
        with self.client.delete(resource) as res:
            res.raise_for_status()

    @property
    def xml(self):
        if self._xml is None:
            self.update()
        return self._xml

    @property
    def bucket_name(self):
        return self.xml.attrib['BucketName']

    @property
    def priority(self):
        return self.xml.attrib['Priority']

    @property
    def type(self):
        return self.xml.attrib['RequestType']

    @property
    def cached_size(self):
        return int(self.xml.attrib['CachedSizeInBytes'])

    @property
    def original_size(self):
        return int(self.xml.attrib['OriginalSizeInBytes'])

    @property
    def is_completed(self):
        self.update()
        return self.cached_size == self.original_size

    @property
    def optimization(self):
        return self.xml.attrib['WriteOptimization']

    # TODO define other getters for the rest of the response xml
    # ...

    @property
    def bucket(self):
        return Bucket(self.client,
            name=self.bucket_name,
        )

    def chunks(self, num_of_chunks=1):
        # TODO need to think about this some more - doing this properly?
        '''
        Return a generator for  a number of chunks ready for processing
        
        This method is supposed to be called multiple times until
        all chunks of a job are uploaded. Do note that it will only
        return the next list of chunks when the previous list of chunks 
        are recorded being uploaded into cache. And there is a certain
        amount of delay for the DS3 server to record a chunk is uploaded
        to cache.
        :param num_of_chunks: preferred number of chunks, this method
                              will return this many chunks or fewer if 
                              it reaches the end
        :Example: 
            uploaded_size = 0
            while (True):
                for chunk in job.chunks:
                    try:
                        upload chunk
                    except Conflict:
                        pass
                if job.xml.attrib['CachedSizeInBytes'] \
                    == job.xml.attrib['OriginalSizeInBytes']:
                    break

        '''
        resource = '/_rest_/job_chunk/'
        
        params = {
            'job': self.id,
            'preferred_number_of_chunks': num_of_chunks,
        }
        with self.client.get(resource, params=params) as res:
            if res.status_code == 404:
                return
            res.raise_for_status()
            root = etree.fromstring(res.text)
            for chunk in root.findall('./Objects'):
                yield [
                    (Key(self.client,
                        name=key.attrib['Name'],
                        bucket_name=self.bucket_name,
                    ),
                    int(key.attrib['Offset']),
                    int(key.attrib['Length']),
                    ) for key in chunk.findall('Object')]

class Jobs(Query):
    '''
    DS3 Jobs View

    Provides a job-centric view of the client.
    '''
    RESOURCE = '/_rest_/job/'

    def __init__(self, client, **params):
        self.client = client
        self.params = params

    def __call__(self, bucket=None, **params):
        return self.filter(bucket=bucket, **params)

    def __iter__(self):
        # TODO if job filtering gets fixed, remove this hack - see below
        params = self.params
        self.params = dict(self.params)
        job_id = self.params.pop('id',str())
        resource = self.RESOURCE
        self.RESOURCE = urlparse.urljoin(self.RESOURCE, job_id)
        
        with self.client.get(self.RESOURCE, params=self.params) as res:
            res.raise_for_status()
            root = etree.fromstring(res.text)
            for job in root.findall('./Job'):
                yield Job.fromxml(self.client, job)
            
            # TODO if job filtering gets fixed, remove this hack
            if root.tag == 'MasterObjectList':
                yield Job.fromxml(self.client, root)
        
        # TODO if job filtering gets fixed, remove this hack - see above
        self.RESOURCE = resource
        self.params = params

    def filter(self, **params):
        p = dict(self.params)
        p.update(params)
        return Jobs(self.client, **p)

    def put(self, bucket, *keys, **params):
        '''
        Create a job to stream PUT object requests
        :params max_upload_size:   max chunk size, default 100GB
        :params priority:          the priority for processing this job, default
                                   to bucket priority
        :params optimize:          options: 
                                   PERFORMANCE: use as many drivers as possible
                                   CAPACITY: use as few tapes as possible
        return: the newly created Job
        '''
        root = etree.Element('Objects')
        
        # Job priority.
        priority = params.pop('priority', None)
        if priority not in set([LOW, NORMAL, HIGH, URGENT, None]):
            raise DS3Exception('Invalid priority: %s' % str(priority))
        if priority is not None:
            root.attrib['Priority'] = priority
        
        # Tape optimization.
        optimize = params.pop('optimize', None)
        if optimize not in set([OPTIMIZE_DISK, OPTIMIZE_PERF, None]):
            raise DS3Exception('Invalid optimization: %s' % str(optimize))
        if optimize is not None:
            root.attrib['WriteOptimization'] = optimize
        
        for key in keys:
            
            obj = etree.Element('Object')
            root.append(obj)
            
            obj.attrib['name'] = key[0]
            obj.attrib['size'] = str(int(key[1]))
        
        resource = '/_rest_/bucket/{bucket}/'.format(bucket=bucket)
        params['operation'] = 'START_BULK_PUT'
        headers = {
            'Content-Type': 'application/xml',
        }
        data = etree.tostring(root)
        with self.client.put(resource, params=params, headers=headers, data=data) as res:
            res.raise_for_status()
            return Job.fromxml(self.client, etree.fromstring(res.text))

    def get(self, bucket, *keys, **params):
        root = etree.Element('Objects')
        
        # Job priority.
        priority = params.pop('priority', None)
        if priority not in set([LOW, NORMAL, HIGH, URGENT, None]):
            raise DS3Exception('Invalid priority: %s' % str(priority))
        if priority is not None:
            root.attrib['Priority'] = priority
        
        # Chunk ordering.
        order = params.pop('order', None)
        if order not in set ([IN_ORDER, NO_ORDER, None]):
            raise DS3Exception('Invalid ordering: %s' % str(order))
        if order is not None:
            root.attrib['chunkClientProcessingOrderGuarantee'] = order
        
        for key in keys:
            
            obj = etree.Element('Object')
            root.append(obj)
            
            obj.attrib['Name'] = key[0]
            try:
                obj.attrib['length'] = str(int(key[1]))
                obj.attrib['offset'] = str(int(key[2]))
            except IndexError:
                pass
        
        resource = '/_rest_/bucket/{bucket}/'.format(bucket=bucket)
        params['operation'] = 'START_BULK_GET'
        headers = {
            'Content-Type': 'application/xml',
        }
        data = etree.tostring(root)
        
        with self.client.put(resource, params=params, headers=headers, data=data) as res:
            res.raise_for_status()
            return Job.fromxml(self.client, etree.fromstring(res.text))

    def delete(self, id):
        '''
        Delete a job.
        '''
        resource = urlparse.urljoin(self.RESOURCE, str(id))
        with self.client.delete(resource) as res:
            res.raise_for_status()

class Client(object):
    '''
    DS3 Client
    '''

    def __init__(self, host, port, **opts):
        self.host = host
        self.port = port
        self.auth = DS3Auth(
            opts.pop('access_key'),
            opts.pop('secret_key'),
        )
        self.protocol = opts.pop('protocol','https')
        self.opts = opts
        
        self.keepalive = False

    @property
    def buckets(self):
        return Buckets(self)

    @property
    def jobs(self):
        return Jobs(self)

    @property
    def keys(self):
        return Keys(self)

    @contextmanager
    def request(self, verb, path, **kwargs):
        # Copy default options.
        opts = dict(self.opts)
        opts.update(kwargs)
        
        # Make the request.
        # TODO should prolly be using urlparse or something...
        res = requests.request(verb,
            '{protocol}://{host}:{port}{path}'.format(
                protocol=self.protocol,
                host=self.host,
                port=self.port,
                path=path
            ),
            auth=self.auth,
            **opts
        )
        
        # Inject response into context.
        yield res
        
        if not self.keepalive:
            # Ensure teardown of the connection.
            res.close()

    @contextmanager
    def get(self, path, **kwargs):
        with self.request('GET', path, **kwargs) as res:
            yield res

    @contextmanager
    def put(self, path, **kwargs):
        with self.request('PUT', path, **kwargs) as res:
            yield res

    @contextmanager
    def post(self, path, **kwargs):
        with self.request('POST', path, **kwargs) as res:
            yield res

    @contextmanager
    def head(self, path, **kwargs):
        with self.request('HEAD', path, **kwargs) as res:
            yield res

    @contextmanager
    def patch(self, path, **kwargs):
        with self.request('PATCH', path, **kwargs) as res:
            yield res

    @contextmanager
    def delete(self, path, **kwargs):
        with self.request('DELETE', path, **kwargs) as res:
            yield res

    @property
    def details(self):
        details = dict()
        details['capacity'] = self.capacity
        return details

    @property
    def capacity(self):
        capacity = dict()
        with self.get('/_rest_/system_capacity_summary/') as res:
            res.raise_for_status()
            root = etree.fromstring(res.text)
            for i in root.findall('./*'):
                capacity[i.tag] = int(i.text)
        return capacity

#
# End pulled from python-ds3sdk
#

def parse_cmd_args():
    parser = ArgumentParser()
    parser.add_argument("bucket_name", 
        help="bucket name to download key from",
    )
    parser.add_argument("key_name", 
        help="key name to download",
    )
    parser.add_argument("--chunk_size",
        help="download chunk size",
        default=16777216
    )
    parser.add_argument("--dl_path",
        help="where to download file",
    )
    
    args = parser.parse_args()
    
    return args

def start_bulk_get(client, bucket, keys, priority):
    # create xml
    root = etree.Element(
        "Objects"
    )
    for key in keys:
        root.append(etree.Element(
            "Object",
            Name=key
            )
        )

    data = etree.tostring(root)
    params = {} 
    params['operation'] = "START_BULK_GET"
    params['priority'] = priority
    params['chunk_client_processing_order_guarantee'] = "NONE"

    print "Starting bulk get"
    with client.put("/_rest_/bucket/%s/" % bucket, data=data, params=params) as res:
        return etree.fromstring(res.text)

def get_ds3_keys_info(client, bucket, keys):
    # create xml
    root = etree.Element(
            "Objects", 
            )

    if isinstance(keys, list):
        for key in keys:
            root.append(etree.Element(
                "Object",
                Name=key
                )
            )
    else:
        root.append(etree.Element(
            "Object",
            Name=keys
            )
        )

    data = etree.tostring(root)
    params = {}
    params['operation'] = "GET_PHYSICAL_PLACEMENT"
    params['full_details'] = ""

    with client.put("/_rest_/bucket/%s/" % bucket, data=data, params=params) as res:
        return etree.fromstring(res.text)

def get_job_chunks(client, job_id, max_chunks=100):

    params = {}
    params['job'] = job_id
    params['preferred_number_of_chunks'] = max_chunks

    with client.get("/_rest_/job_chunk/", params=params) as res:
        return etree.fromstring(res.text), res.headers

def get_ds3_job_chunks_in_order(client, job_id):
    all_chunks = {}
    retries = 0
    getting_objects = True
    order_retries_before_exiting = 200
    sleep_time_between_retries = 15
    while getting_objects:
        # get the current list of objects
        job_chunks, header = get_job_chunks(client, job_id)
        total_bytes = int(job_chunks.get("OriginalSizeInBytes"))
        for field in job_chunks:
            if field.tag == "Objects":
                for chunk in field:
                    # add them to a set dict
                    if int(chunk.get("Offset")) not in all_chunks:
                        all_chunks[int(chunk.get("Offset"))] = {
                            'InCache': chunk.get("InCache") in ['true', 'True'],
                            'Length': int(chunk.get("Length")),
                            'Complete': False
                        }
                    else:
                        all_chunks[int(chunk.get("Offset"))] = {
                            'InCache': chunk.get("InCache") in ['true', 'True'],
                            'Length': int(chunk.get("Length")),
                        }
        misorder = False
        cur_offset = 0
        if len(all_chunks):
            for offset in sorted(all_chunks.keys()):
                if cur_offset != offset:
                    print "Oops, we have a mismatch for job %s:cur %d, expected %d, waiting (%d retries)" % (
                        job_id,
                        offset, cur_offset, retries
                    )
                    misorder = True
                    time.sleep(sleep_time_between_retries)
                    retries += 1
                    if retries >= order_retries_before_exiting:
                        print etree.tostring(job_chunks, pretty_print=True)
                        misorder = True
                        getting_objects = False
                    break
                else:
                    cur_offset = offset + all_chunks[offset]['Length']

            if not misorder:
                sys.stdout.write("All chunks proper and in order...")
                if cur_offset < total_bytes:
                    print "but %d bytes not accounted for. Waiting for remaining chunks" % (total_bytes - cur_offset)
                    time.sleep(sleep_time_between_retries)
                    retries += 1
                else:
                    print "and all bytes accounted for, what a lovely day."
                    getting_objects = False
        else:
            time.sleep(sleep_time_between_retries)

    if misorder:
        print "Unable to fetch chunks in order"
        all_chunks = {}

    return all_chunks

def download_ds3_key(client, bucket, key, chunk_size, target_filename=None):
    params = {}
    key_str = '/%s/%s' % (bucket, key)
    bytes_transferred = 0

    key_info = get_ds3_keys_info(client, bucket, key)
    file_size = 0
    for object in key_info:
        
        file_size += int(object.get("Length"))
    # start a bulk get
    job_data = start_bulk_get(client, bucket, [key], "NORMAL")
    
    # get job chunks
    params['job'] = job_data.get("JobId")
    print "Getting chunks for job %s" % params['job']
    data = get_ds3_job_chunks_in_order(client, params['job'])

    if not target_filename:
        download_filename = key
    else:
        download_filename = target_filename

    if len(data):
        with open(download_filename, "wb") as out_file:
            # start downloading
            for offset in sorted(data.keys()):
                params['offset'] = str(offset)
                with client.get(key_str, params=params, stream=True) as res:
                    try:
                        res.raise_for_status()
                    except:
                        print "Unable to find %s, %d %s" % (key_str, res.status_code, res.reason)
                        running = False
                    else:
                        for chunk in res.iter_content(chunk_size=chunk_size):

                            if len(chunk) < chunk_size:
                                running = False
                            bytes_transferred += len(chunk)
                            percent_done = (float(bytes_transferred) / float(file_size)) * 100.0
                            sys.stdout.write("%6.02f%%\r" % percent_done)
                            sys.stdout.flush()
                            if bytes_transferred > file_size:
                                print
                                print "Warning, file size exceeded (%d/%d)" % (
                                    bytes_transferred, file_size)
                                running = False
                            out_file.write(chunk)
                            retries = 0
                        error = False

    print "Download complete"

args = parse_cmd_args()

host = os.environ['DS3_HOST']
port = os.environ['DS3_PORT']
secret_key = secret_key=os.environ['DS3_SECRET_KEY']
access_key = access_key=os.environ['DS3_ACCESS_KEY']

conn = Client(
    host, port,
    access_key=access_key,
    secret_key=secret_key,
    verify=False
    )

if args.dl_path:
    if not os.path.isdir(args.dl_path):
        os.mkdir(args.dl_path)
    filename = "%s/%s" % (args.dl_path.rstrip('/'), args.key_name)
else:
    filename = args.key_name

# download the file
print "Downloading to %s" % filename
download_ds3_key(conn, args.bucket_name, args.key_name, args.chunk_size, filename)


