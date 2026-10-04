#!/usr/bin/env python3
"""Opt-in real-client ACL benchmark; see integration/README.md."""
import argparse
import concurrent.futures
import datetime
import json
import os
from pathlib import Path
import shlex
import subprocess
import threading
import time
import uuid


class Host:
    def __init__(self, spec, run):
        self.name = spec['name']
        self.ssh = spec.get('ssh')
        self.docker = spec.get('docker', 'docker')
        self.reserve = spec['reserve_gib']
        self.cap = spec['client_cap']
        self.label = 'headscale.scale-run=' + run
        self.socket = '/tmp/hs-scale-' + run + '-' + self.name
        self.prefix = []
        if self.ssh:
            options = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', '-o', 'ControlPersist=3600', '-S', self.socket]
            subprocess.run(['ssh', *options, '-MNf', '-o', 'ControlMaster=yes', self.ssh], check=True)
            self.prefix = ['ssh', *options, self.ssh]

    def command(self, args, data=None, timeout=120, check=True):
        command = self.prefix + [shlex.join(args)] if self.ssh else args
        result = subprocess.run(command, input=data, text=True, capture_output=True, timeout=timeout)
        if check and result.returncode:
            # Never include command arguments or auth-key stdout in diagnostics.
            raise RuntimeError(f'{self.name}: command failed ({result.returncode}): {result.stderr[-300:]}')
        return result

    def run(self, args, **kwargs):
        return self.command([self.docker, *args], **kwargs)

    def memory(self, image):
        output = self.run(['run', '--rm', '--label', self.label, '--network', 'none', '--entrypoint', 'cat', image, '/proc/meminfo']).stdout
        mem = {line.split(':')[0]: int(line.split()[1]) for line in output.splitlines()}
        return {'available_gib': mem['MemAvailable'] / 1024**2,
                'swap_mib': (mem['SwapTotal'] - mem['SwapFree']) / 1024}

    def close(self):
        if self.ssh:
            subprocess.run(['ssh', '-S', self.socket, '-O', 'exit', self.ssh], capture_output=True)


def parallel(function, values, workers=8):
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(function, values))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec', required=True, help='JSON host specification; read the README first')
    parser.add_argument('--iot-stages', default='100,500,1000,1300,1400,1500,1600,1700,1800,2000')
    parser.add_argument('--segments', type=int, default=100)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    spec = json.loads(Path(args.spec).read_text())
    stages = [int(value) for value in args.iot_stages.split(',')]
    assert args.segments >= 2 and stages == sorted(set(stages))
    assert all(value > 0 and value % args.segments == 0 for value in stages)
    run = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S') + uuid.uuid4().hex[:4]
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    ledger = (output / 'phases.jsonl').open('w')
    hosts = []
    clients = []
    networks = []
    originals = {}
    stopped = threading.Event()
    resource_error = []
    monitor = None
    server = 'hs-distributed-' + run
    label = 'headscale.scale-run=' + run
    image = spec['client_image']

    def phase(name, **values):
        row = {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'run': run, 'phase': name, **values}
        ledger.write(json.dumps(row) + '\n')
        ledger.flush()
        os.fsync(ledger.fileno())
        print(json.dumps(row), flush=True)

    def guard():
        if resource_error:
            raise RuntimeError('resource guard: ' + resource_error[0])

    try:
        hosts = [Host(host, run) for host in spec['hosts']]
        linux = hosts[0]
        baseline = {host.name: host.memory(image) for host in hosts}
        phase('baseline', memory=baseline)
        # Runtime-only tuning, checked and restored in finally.
        for family in ['ipv4', 'ipv6']:
            for number, value in [(1, 4096), (2, 16384), (3, 65536)]:
                key = f'net.{family}.neigh.default.gc_thresh{number}'
                originals[key] = int(linux.command(['sysctl', '-n', key]).stdout)
                linux.command(['sysctl', '-w', key + '=' + str(value)])
        (output / 'sysctl-before.json').write_text(json.dumps(originals))
        for host in hosts:
            for index in range(4):
                name = f'hs-scale-{run}-{host.name}-{index}'
                host.run(['network', 'create', '--label', label, name])
                networks.append((host, name))
            phase('client_version', host=host.name, version=host.run(['run', '--rm', '--network', 'none', '--entrypoint', 'tailscale', image, 'version']).stdout.strip(), image=host.run(['image', 'inspect', '--format', '{{.Id}}', image]).stdout.strip())
        server_dir = spec['server_dir'] + '/' + run
        linux.command(['mkdir', '-p', server_dir])
        linux.command(['cp', *[spec['server_dir'] + '/' + name for name in ['config.json', 'ca.crt', 'key.pem']], server_dir])
        linux.run(['run', '-d', '--name', server, '--label', label, '--memory', '8g', '--cpus', '8',
                   '--ulimit', 'nofile=65536:65536', '-v', server_dir + ':/bench',
                   '-p', '10.59.0.16:18443:18443/tcp', '-p', '10.59.0.16:3478:3478/udp',
                   '--entrypoint', 'headscale', spec['server_image'], 'serve', '--config', '/bench/config.json'])

        def cli(*command):
            return linux.run(['exec', server, 'headscale', '--config', '/bench/config.json', *command]).stdout

        def eventually(function, timeout=180):
            until = time.monotonic() + timeout
            last = 'not ready'
            while time.monotonic() < until:
                guard()
                try:
                    return function()
                except (RuntimeError, AssertionError, json.JSONDecodeError) as error:
                    last = str(error)
                    time.sleep(1)
            raise RuntimeError('convergence timeout: ' + last)

        eventually(lambda: linux.run(['exec', server, 'curl', '-fsS', '--cacert', '/bench/ca.crt', spec['url'] + '/health']))
        readers = ['scale-reader-' + str(i) for i in range(args.segments)]
        users = ['scale-admin', *readers]
        for user in [*users, *['scale-iot-' + str(i) for i in range(args.segments)]]:
            cli('users', 'create', user)
        keys = {}
        for user in users:
            keys[user] = json.loads(cli('preauthkeys', 'create', '--user', user, '--reusable', '--expiration', '2h', '-o', 'json'))['key']
        for i in range(args.segments):
            keys['scale-iot-' + str(i)] = json.loads(cli('preauthkeys', 'create', '--user', 'scale-iot-' + str(i), '--reusable', '--expiration', '2h', '--tags', f'tag:iot,tag:segment-{i}', '-o', 'json'))['key']

        def set_policy(revoked):
            owners = {'tag:iot': ['scale-admin@']}
            rules = [{'action': 'accept', 'src': ['scale-admin@'], 'dst': ['100.64.0.0/16:*', 'tag:iot:*']}]
            rules += [{'action': 'accept', 'src': [user + '@'], 'dst': [user + '@:*']} for user in users]
            for i, user in enumerate(readers):
                owners['tag:segment-' + str(i)] = ['scale-admin@']
                if not revoked or i != 0:
                    rules.append({'action': 'accept', 'src': [user + '@'], 'proto': 'tcp', 'dst': [f'tag:segment-{i}:80,443']})
            policy = {'tagOwners': owners, 'acls': rules, 'nodeAttrs': [
                {'target': ['autogroup:member'], 'ipPool': ['100.65.0.0/16']},
                {'target': ['tag:iot'], 'ipPool': ['100.64.0.0/16']}]}
            linux.run(['exec', '-i', server, 'sh', '-c', 'cat > /bench/policy.json'], data=json.dumps(policy))
            cli('policy', 'set', '--file', '/bench/policy.json')

        set_policy(False)

        def watch():
            with (output / 'resources.jsonl').open('w') as log:
                while not stopped.is_set():
                    try:
                        memory = {host.name: host.memory(image) for host in hosts}
                        stats = linux.run(['stats', '--no-stream', '--format', '{{json .}}', server]).stdout.strip()
                        rss = linux.run(['exec', server, 'cat', '/proc/1/status'], check=False).stdout
                        row = {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'clients': len(clients), 'memory': memory, 'server_stats': stats, 'server_status': rss}
                        log.write(json.dumps(row) + '\n'); log.flush()
                        for host in hosts:
                            mem = memory[host.name]
                            if mem['available_gib'] < host.reserve or mem['swap_mib'] - baseline[host.name]['swap_mib'] > 512:
                                resource_error.append(host.name + ': RAM/swap reserve reached')
                                return
                    except Exception as error:
                        # Restart can temporarily prevent exec; guard monitoring continues.
                        log.write(json.dumps({'monitor_error': str(error)}) + '\n'); log.flush()
                    stopped.wait(10)

        monitor = threading.Thread(target=watch, daemon=True)
        monitor.start()

        def enroll(item):
            host, name, user, segment, role = item
            command = 'printf "headscale-scale-ok\\n" > /tmp/acl-check; httpd -p 80 -h /tmp; exec tailscaled --state=/tmp/tailscaled.state --socket=/tmp/tailscaled.sock --tun=tailscale0 --port=0'
            host.run(['run', '-d', '--name', name, '--hostname', name, '--label', label, '--memory', '192m', '--pids-limit', '64',
                      '--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun', '--network', f'hs-scale-{run}-{host.name}-{segment % 4}',
                      '--entrypoint', 'sh', image, '-c', command])
            client = {'host': host, 'name': name, 'user': user, 'segment': segment, 'role': role}
            clients.append(client)
            host.run(['exec', name, 'tailscale', '--socket=/tmp/tailscaled.sock', 'up', '--login-server=' + spec['url'],
                      '--authkey=' + keys[user], '--accept-dns=false', '--netfilter-mode=off', '--hostname=' + name], timeout=120)
            return client

        host_counts = {host.name: 0 for host in hosts}
        def choose_host(index):
            # Fill bounded Mac capacity first; Linux receives the remainder.
            host = hosts[1 + index % (len(hosts) - 1)] if len(hosts) > 1 else linux
            if host_counts[host.name] >= host.cap:
                host = linux
            assert host_counts[host.name] < host.cap, 'generator client cap reached'
            host_counts[host.name] += 1
            return host

        personal = []
        for i, user in enumerate(users):
            for device in range(2):
                host = choose_host(i * 2 + device)
                personal.append((host, f'ts-{run}-p-{i}-{device}', user, i - 1, 'personal'))
        parallel(enroll, personal)
        phase('personal_ready', clients=len(clients), placement=host_counts)

        def status(client):
            return json.loads(client['host'].run(['exec', client['name'], 'tailscale', '--socket=/tmp/tailscaled.sock', 'status', '--json']).stdout)

        def all_connected():
            info = json.loads(linux.run(['exec', server, 'curl', '-fsS', '-H', 'Accept: application/json', 'http://127.0.0.1:9090/debug/batcher']).stdout)
            assert sum(n['connected'] and n['active_connections'] > 0 for n in info['connected_nodes'].values()) == len(clients), 'Noise streams incomplete'

        def maps(iot_count, revoked=False):
            def check(client):
                def ready():
                    state = status(client)
                    peers = state.get('Peer') or {}
                    expected = iot_count + 1 if client['user'] == 'scale-admin' else iot_count // args.segments + 1
                    if client['role'] == 'iot': expected = 4
                    if revoked and client['segment'] == 0 and client['user'] != 'scale-admin': expected = 2 if client['role'] == 'iot' else 1
                    assert state['BackendState'] == 'Running' and len(peers) == expected, f"{client['name']}: expected {expected} peers, got {len(peers)}"
                    assert all(p['Online'] and p['HostName'] and p.get('Relay') for p in peers.values()), 'peer metadata incomplete'
                    client['ip'] = state['TailscaleIPs'][0]
                eventually(ready)
            parallel(check, list(clients))

        def probe(source, target, allowed):
            def check():
                result = source['host'].run(['exec', source['name'], 'curl', '--noproxy', '*', '-fsS', '--connect-timeout', '3', '--max-time', '4', 'http://' + target['ip'] + '/acl-check'], check=False)
                assert (result.returncode == 0 and result.stdout.strip() == 'headscale-scale-ok') if allowed else result.returncode != 0, 'TCP access mismatch'
            eventually(check, timeout=60)

        previous = 0
        for count in stages:
            guard(); set_policy(False)
            jobs = []
            for i in range(previous, count):
                segment = i % args.segments
                host = choose_host(i)
                jobs.append((host, f'ts-{run}-i-{i}', 'scale-iot-' + str(segment), segment, 'iot'))
            # Batches keep resource guard responsive and below SSH session limits.
            for offset in range(0, len(jobs), 8):
                guard(); parallel(enroll, jobs[offset:offset+8])
                phase('enroll', iot=previous + min(offset + 8, len(jobs)), clients=len(clients))
            eventually(all_connected); maps(count)
            reader = next(c for c in clients if c['user'] == readers[0])
            own = next(c for c in clients if c['user'] == readers[0] and c is not reader)
            admin = next(c for c in clients if c['user'] == 'scale-admin')
            own_iot = next(c for c in clients if c['role'] == 'iot' and c['segment'] == 0)
            foreign = next(c for c in clients if c['user'] == readers[1])
            remote_iot = next(c for c in clients if c['role'] == 'iot' and c['host'] is not admin['host'])
            probe(reader, own, True); probe(reader, own_iot, True); probe(reader, foreign, False); probe(admin, remote_iot, True)
            phase('ready', iot=count, clients=len(clients), placement=host_counts)
            restart = time.monotonic()
            linux.run(['restart', '--time', '5', server])
            eventually(all_connected)
            phase('all_streams_reconnected', clients=len(clients), seconds=time.monotonic()-restart)
            maps(count)
            revoke = time.monotonic(); set_policy(True)
            phase('policy_applied', seconds=time.monotonic()-revoke)
            probe(reader, own_iot, False)
            phase('packet_denied', seconds=time.monotonic()-revoke)
            maps(count, True); probe(admin, own_iot, True); probe(reader, own, True)
            phase('complete', iot=count, clients=len(clients), placement=host_counts)
            previous = count
        phase('scenario_pass')
    except Exception as error:
        phase('stopped', error=str(error))
        raise
    finally:
        stopped.set()
        if monitor: monitor.join(timeout=30)
        if hosts:
            linux = hosts[0]
            try:
                # Keep the complete log on its originating host before removing
                # the container, without transferring it through SSH stdout.
                linux.command(['python3', '-c',
                    'import subprocess,sys; '
                    'f=open(sys.argv[1], "w"); '
                    'subprocess.run(["docker", "logs", sys.argv[2]], '
                    'stdout=f, stderr=f, timeout=30)',
                    spec['server_dir'] + '/' + run + '/headscale-full.log', server], timeout=35)
            except (subprocess.TimeoutExpired, RuntimeError) as error:
                phase('artifact_failed', artifact='full_remote_log', error=str(error))
            # Artifact failure must never bypass cleanup. Bound log transfer:
            # the complete Docker log remains on the Linux host for analysis.
            for filename, command in [
                ('headscale.log', ['logs', '--tail', '20000', server]),
                ('metrics.txt', ['exec', server, 'curl', '-fsS', 'http://127.0.0.1:9090/metrics']),
            ]:
                try:
                    result = linux.run(command, check=False, timeout=30)
                    (output / filename).write_text(result.stdout + result.stderr)
                except (subprocess.TimeoutExpired, RuntimeError) as error:
                    phase('artifact_failed', artifact=filename, error=str(error))
            for host in hosts:
                names = host.run(['ps', '-a', '--filter', 'label=' + label, '--format', '{{.Names}}']).stdout.splitlines()
                for offset in range(0, len(names), 30):
                    host.run(['rm', '-f', *names[offset:offset+30]], timeout=180, check=False)
            for host, network in networks:
                host.run(['network', 'rm', network], check=False)
            for key, value in originals.items():
                current = int(linux.command(['sysctl', '-n', key]).stdout)
                expected = {1:4096, 2:16384, 3:65536}[int(key[-1])]
                if current != expected: raise RuntimeError('sysctl changed concurrently: ' + key)
                linux.command(['sysctl', '-w', key + '=' + str(value)])
            phase('cleaned')
            for host in hosts: host.close()
        ledger.close()


if __name__ == '__main__':
    main()
