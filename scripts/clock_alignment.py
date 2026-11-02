"""Clock calibration for Tracee 0.24 on local WSL; raw sensor bytes stay intact.

Tracee's tracee_info exports the constant boot_time added to BPF BOOTTIME.
Invert that exact addition, then use measured BOOTTIME-MONOTONIC. PCAP uses
REALTIME, inverted with densely bracketed samples. Ambiguity is bounded and
reported, never silently treated as an exact timestamp.
"""
import bisect
import math

REVISION = 'tracee-boot-monotonic-r1'
LIMIT = .005


class ClockAlignment:
    def __init__(self, samples):
        if len(samples) < 2:
            raise ValueError('Clock samples missing')
        self.samples = samples
        if any(not all(math.isfinite(r[k]) for k in ('timestamp','monotonic','boottime','sampling_uncertainty_seconds')) for r in samples):
            raise ValueError('Nonfinite clock calibration')
        if any(b['monotonic'] <= a['monotonic'] for a,b in zip(samples,samples[1:])):
            raise ValueError('Clock monotonic order invalid')
        offsets = [r['boottime']-r['monotonic'] for r in samples]
        self.boot_offset = (min(offsets)+max(offsets))/2
        self.boot_uncertainty = (max(offsets)-min(offsets))/2 + max(r['sampling_uncertainty_seconds'] for r in samples)
        if self.boot_uncertainty > LIMIT:
            raise ValueError('BOOTTIME-MONOTONIC calibration unstable')
        self.wall = [r['timestamp'] for r in samples]
        self.ordered = all(b >= a for a,b in zip(self.wall,self.wall[1:]))
        self.max_uncertainty = 0
        self.mapped_packets = 0

    def endpoint(self, timestamp_ns, tracee_boot_ns):
        return (int(timestamp_ns)-int(tracee_boot_ns))/1e9-self.boot_offset

    def packet(self, timestamp):
        # In a forward step, two candidate offsets are considered. Candidates
        # outside the measured monotonic bracket cannot describe this packet.
        if self.ordered:
            i=bisect.bisect_right(self.wall,timestamp)-1
            indices=[i] if 0 <= i < len(self.samples)-1 else []
        else:
            indices=[i for i,(a,b) in enumerate(zip(self.samples,self.samples[1:]))
                     if min(a['timestamp'],b['timestamp']) <= timestamp <= max(a['timestamp'],b['timestamp'])]
        possible=[]
        for i in indices:
            a,b=self.samples[i:i+2]
            oa,ob=a['timestamp']-a['monotonic'],b['timestamp']-b['monotonic']
            uncertainty=max(a['sampling_uncertainty_seconds'],b['sampling_uncertainty_seconds'])+1e-6
            if abs(ob-oa) < .001:
                fraction=(timestamp-a['timestamp'])/(b['timestamp']-a['timestamp']) if b['timestamp']!=a['timestamp'] else .5
                estimate=a['monotonic']+fraction*(b['monotonic']-a['monotonic'])
                possible.extend([estimate-abs(ob-oa)/2-uncertainty,estimate+abs(ob-oa)/2+uncertainty])
            else:
                for offset in (oa,ob):
                    estimate=timestamp-offset
                    if a['monotonic']-uncertainty <= estimate <= b['monotonic']+uncertainty:
                        possible.extend([estimate-uncertainty,estimate+uncertainty])
        if not possible:
            raise ValueError('PCAP timestamp outside clock calibration')
        lo,hi=min(possible),max(possible)
        uncertainty=(hi-lo)/2
        if uncertainty > LIMIT:
            raise ValueError('PCAP clock ambiguity exceeds 5ms')
        self.max_uncertainty=max(self.max_uncertainty,uncertainty)
        self.mapped_packets+=1
        return (hi+lo)/2,uncertainty

    def report(self):
        offsets=[r['timestamp']-r['monotonic'] for r in self.samples]
        return {'revision':REVISION,'raw_timestamps_preserved':True,'samples':len(self.samples),
                'realtime_offset_spread_seconds':max(offsets)-min(offsets),
                'boot_monotonic_uncertainty_seconds':self.boot_uncertainty,
                'packet_alignment_max_uncertainty_seconds':self.max_uncertainty,
                'mapped_packets':self.mapped_packets,'limit_seconds':LIMIT}


def tracee_boot_time(raw):
    info=[r for r in raw if r['eventName']=='tracee_info']
    if len(info)!=1:
        raise ValueError('Exactly one Tracee boot calibration event required')
    args={a['name']:a['value'] for a in info[0]['args']}
    if '0.24.1' not in args['version']:
        raise ValueError('Unexpected Tracee clock version')
    return int(args['boot_time'])
