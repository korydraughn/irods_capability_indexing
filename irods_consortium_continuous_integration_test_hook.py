from __future__ import print_function

import optparse
import os
import re
import shutil
import glob
import tempfile
import irods_python_ci_utilities
import base64

def Indexing_PackageName_Regex( package_ext, technology = 'elasticsearch' ):
    tech = re.escape(technology)
    ext = re.escape(package_ext)
    return re.compile(
        r'irods-rule-engine-plugin-({tech}|indexing)[-_][0-9].*\.{ext}$'.format(**locals())
    )

def get_matching_packages(directory,ext):
    pattern = Indexing_PackageName_Regex(ext)
    return [ os.path.join(directory,y) for y in os.listdir(directory) if pattern.match(y) ]

def get_build_prerequisites_all():
    return['gcc', 'swig']

def platform_including_major_revision():
    return ( irods_python_ci_utilities.get_distribution(),
             irods_python_ci_utilities.get_distribution_version_major() )

def get_build_prerequisites_apt():
    return get_build_prerequisites_all() + [
        'curl',
        'libsasl2-2',
        'libsasl2-dev',
        'libssl-dev',
        'python3-dev',
        'python3-pip',
        'uuid-dev'
    ]

def get_build_prerequisites_yum():
    return get_build_prerequisites_all() + [
        'ca-certificates',
        'cyrus-sasl-devel',
        'libuuid-devel',
        'openssl-devel',
        'python3-devel',
        'python3-pip',
        'which'
    ]

def get_build_prerequisites_zypper():
    return get_build_prerequisites_all() + [
        'ca-certificates',
        'curl',
        'python3-pip',
        'which'
    ]

def get_build_prerequisites():
    dispatch_map = {
        'Almalinux': get_build_prerequisites_yum,
        'Centos linux': get_build_prerequisites_yum,
        'Centos': get_build_prerequisites_yum,
        'Debian gnu_linux': get_build_prerequisites_apt,
        'Opensuse': get_build_prerequisites_zypper,
        'Rocky linux': get_build_prerequisites_yum,
        'Ubuntu': get_build_prerequisites_apt
    }
    try:
        distribution, major_version_number = platform_including_major_revision()
        pkgs = dispatch_map[distribution]()

        # The "swig" package is only available via the "crb" repository in
        # Rocky Linux 9. The "crb" repository must be enabled before attempting
        # to install the "swig" package.
        if ('Rocky linux', '9') == (distribution, major_version_number):
            pkgs.remove('swig')
            irods_python_ci_utilities.subprocess_get_output(
                'sudo dnf config-manager --set-enabled crb && sudo dnf install -y swig', shell=True)

        return pkgs
    except KeyError:
        irods_python_ci_utilities.raise_not_implemented_for_distribution()

def install_build_prerequisites():
    irods_python_ci_utilities.install_os_packages(get_build_prerequisites())

class IndexerNotImplemented (RuntimeError): pass
class WrongNumberOfGlobResults (RuntimeError): pass

# Global variables for elasticsearch.
# These variables capture important information needed by iRODS for proper
# communication with elasticsearch.
es_auth_basic_creds = None
es_password = None
es_pid = None
es_tls_cert_file = None

def install_indexing_engine(indexing_engine):
    if 'elasticsearch' in indexing_engine.lower():
        es_name = 'elasticsearch-8.12.2'

        temp_dir = tempfile.mkdtemp()
        url = f'https://artifacts.elastic.co/downloads/elasticsearch/{es_name}-linux-x86_64.tar.gz'
        irods_python_ci_utilities.subprocess_get_output(['wget', '-q', url])

        es_home = f'{temp_dir}/{es_name}'

        tar_names = [x for x in url.split('/') if '.tar' in x]
        irods_python_ci_utilities.subprocess_get_output(['tar', '-C', temp_dir, '--no-same-owner', '-xzf', tar_names[-1]])
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'useradd', 'elastic', '-s/bin/bash'])
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'chown', '-R', 'elastic:elastic', temp_dir])

        executables = glob.glob(os.path.join(temp_dir,'*','bin','elasticsearch'))
        if len(executables) != 1 : raise WrongNumberOfGlobResults
        print('executable = ' + str(executables[0]))

        global es_pid
        es_pid = f'{es_home}/daemon_pid'
        irods_python_ci_utilities.subprocess_get_output(
            f'''sudo su elastic -c "{executables[0]} -d -p {es_pid} -E discovery.type=single-node"''', shell=True)

        # Reset the password for the elastic user.
        # Do not allow certain characters in the password. Avoids base64 encoding issues.
        special_chars = set('*:@?&+')
        global es_password
        es_password = ':'
        while any((c in special_chars) for c in es_password):
            print('Resetting password for elastic user ...')
            ec, es_password, _ = irods_python_ci_utilities.subprocess_get_output(
                f'''sudo su elastic -c "{es_home}/bin/elasticsearch-reset-password -u elastic -abs"''', shell=True)
        es_password = es_password.strip()
        print('password reset result = ' + es_password)

        # Capture the encoded credentials for authentication.
        global es_auth_basic_creds
        es_auth_basic_creds = base64.b64encode(('elastic:' + es_password).encode('utf-8')).decode('utf-8')

        # Copy the TLS cert generated by elasticsearch and give iRODS complete ownership of it.
        global es_tls_cert_file
        es_tls_cert_file = f'/http_ca.crt.copied_from_elasticsearch'
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'cp', f'{es_home}/config/certs/http_ca.crt', es_tls_cert_file])
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'chown', 'irods:irods', es_tls_cert_file])

    else:
        raise IndexerNotImplemented

def main():
    parser = optparse.OptionParser()
    parser.add_option('--output_root_directory')
    parser.add_option('--built_packages_root_directory')
    parser.add_option('--indexing_engine', default='elasticsearch', help='Index/Search Platform needed for plugin test')
    parser.add_option('--test', metavar='dotted name')
    parser.add_option('--skip-setup', action='store_false', dest='do_setup', default=True)
    options, _ = parser.parse_args()

    built_packages_root_directory = options.built_packages_root_directory
    package_suffix = irods_python_ci_utilities.get_package_suffix()
    os_specific_directory = irods_python_ci_utilities.append_os_specific_directory(built_packages_root_directory)

    if options.do_setup:
        install_build_prerequisites()

        install_indexing_engine(options.indexing_engine)

        # Packages are put either in top level or os-specific subdirectory.
        # For indexing it seems to be top level for now. But just in case, we check both.
        for directory in ( built_packages_root_directory, os_specific_directory ):
            pkgs = get_matching_packages(directory, package_suffix)
            if pkgs:
                irods_python_ci_utilities.install_os_packages_from_files( pkgs )
                break

    test = options.test or 'test_plugin_indexing'

    test_output_file = 'log/test_output.log'

    try:
        global es_auth_basic_creds
        global es_password
        global es_pid
        global es_tls_cert_file

        env_vars = f'export IRODS_ES_PASSWORD={es_password} IRODS_ES_AUTH_BASIC_CREDS={es_auth_basic_creds} IRODS_ES_TLS_CERT_FILE={es_tls_cert_file}'
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'su', '-', 'irods', '-c',
            f'{env_vars}; python3 scripts/run_tests.py --xml_output --run_s={test} 2>&1 | tee {test_output_file}; exit $PIPESTATUS'],
            check_rc=True)

    finally:
        output_root_directory = options.output_root_directory
        if output_root_directory:
            irods_python_ci_utilities.gather_files_satisfying_predicate('/var/lib/irods/log', output_root_directory, lambda x: True)
            test_output_file = os.path.join('/var/lib/irods', test_output_file)
            if os.path.exists(test_output_file):
                shutil.copy(test_output_file, output_root_directory)

if __name__ == '__main__':
    main()
