from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import pytest
from leakguard_host.protection import validate,defaults,next_run
from leakguard_host.errors import HostError

def test_validation_and_interval_catchup():
 s=defaults()['schedule'];s['interval_seconds']=60
 assert next_run(s,1000)==1060
 for field,value in [('interval_seconds',True),('interval_seconds',59),('daily_time','25:00'),('timezone','invalid/no-such-zone')]:
  bad=dict(s);bad[field]=value
  with pytest.raises(HostError):validate({'schedule':bad})
 with pytest.raises(HostError):validate({'exclusions':['relative']})

def test_daily_spring_gap_and_repeated_hour_are_explicit():
 s={'mode':'daily','interval_seconds':3600,'daily_time':'02:30','timezone':'America/New_York'}
 start=datetime(2026,3,8,0,0,tzinfo=ZoneInfo(s['timezone'])).timestamp()
 got=datetime.fromtimestamp(next_run(s,start),ZoneInfo(s['timezone']))
 assert (got.hour,got.minute)==(3,0)
 s['daily_time']='01:30';start=datetime(2026,11,1,0,0,tzinfo=ZoneInfo(s['timezone'])).timestamp()
 got=datetime.fromtimestamp(next_run(s,start),ZoneInfo(s['timezone']))
 assert (got.hour,got.minute,got.fold)==(1,30,0)
 # A completed first occurrence schedules tomorrow, never the second copy.
 later=next_run(s,got.timestamp()+1)
 assert datetime.fromtimestamp(later,ZoneInfo(s['timezone'])).day==2


def test_global_schedule_changes_persist_and_do_not_override_location_schedule(tmp_path):
 from leakguard_host import HostService
 from leakguard_core.api import ScanConfig
 from test_host import SessionStore
 store=SessionStore();clock=lambda:1700000000.0
 first=defaults();first['schedule']['interval_seconds']=3600
 h=HostService(config=ScanConfig.from_mapping({}),scan_store=store,protection=first,clock=clock);s=h.add_source(tmp_path);h.manage_source(s['id'])
 changed=defaults();changed['schedule']['interval_seconds']=60
 h=HostService(config=ScanConfig.from_mapping({}),scan_store=store,protection=changed,clock=clock)
 assert h.sources()[0]['next_run_at']==datetime.fromtimestamp(clock()+60,timezone.utc).isoformat()
 h.update_source(s['id'],schedule_seconds=120)
 later=defaults();later['schedule']['interval_seconds']=300
 h=HostService(config=ScanConfig.from_mapping({}),scan_store=store,protection=later,clock=clock)
 assert h.sources()[0]['schedule_seconds']==120
 assert h.sources()[0]['next_run_at']==datetime.fromtimestamp(clock()+120,timezone.utc).isoformat()


def test_explicit_user_pause_survives_restart_even_after_system_pause(tmp_path):
 from leakguard_host import HostService
 from leakguard_core.api import ScanConfig
 from test_host import SessionStore
 store=SessionStore();h=HostService(config=ScanConfig.from_mapping({}),scan_store=store);s=h.add_source(tmp_path);h.manage_source(s['id']);j=h.submit(s['id']);h._state['jobs'][j['id']].update(state='paused',last_error='service-stopped');h.pause(j['id'])
 restored=HostService(config=ScanConfig.from_mapping({}),scan_store=store)
 assert restored.job(j['id'])['state']=='paused'
 assert restored.job(j['id'])['pause_reason']=='user'


def test_disabled_automatic_scope_is_visible_as_paused_and_never_dispatched(tmp_path):
 from leakguard_host import HostService
 from leakguard_core.api import ScanConfig
 from test_host import SessionStore
 store=SessionStore();h=HostService(config=ScanConfig.from_mapping({}),scan_store=store)
 h.configure_automatic([tmp_path]);source=h.sources()[0];h.submit(source['id'])
 settings=defaults();settings['automatic_this_mac']=False
 restored=HostService(config=ScanConfig.from_mapping({}),scan_store=store,protection=settings)
 assert restored.sources()[0]['availability']=='paused'
 assert restored.tick()['status']=='idle'
