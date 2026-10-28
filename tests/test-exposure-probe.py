"""Probe safety/control-flow fixtures. No camera or network traffic."""
import importlib.util
from pathlib import Path
import queue
import time
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('exposure_probe',ROOT/'scripts/probe-exposure-preview.py')
probe_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe_module)


class ProbeTests(unittest.TestCase):
    def run_fixture(self, failure=None, mode='M',require_images=False):
        destination=ROOT/'output/exposure-probe-tests'/uuid.uuid4().hex
        destination.mkdir(parents=True)
        probe=probe_module.Probe(destination,timeout=0.05,settle=0,min_frames=1,min_span=0,
                                 image_window=0,require_baseline_image=require_images)
        frames=queue.Queue();clock=time.monotonic()-1
        state={'ExposureMode':mode,'ISOSetting':'100','ColorMode':'HContrastBW','Fnumber':'5.0','ShutterSpeed':'1.3s'}
        calls=[]
        def emit():
            frames.put({'file':'packet_fixture.jpg','elapsedSeconds':time.monotonic()-clock+0.00001,'metadata':dict(state)})
        emit()
        def change(field,value,base):
            calls.append((field,value))
            if failure=='reject-color' and field=='ColorMode' and value=='Standard':
                return {'httpStatus':200,'body':{'code':1000}}
            key='ISOSetting' if field=='ISO' else field
            if not (failure=='restore-metadata-missing' and field=='ISO' and value=='100'):
                state[key]=value
            emit()
            if failure in ('lost-iso-reply','interrupt-iso') and field=='ISO' and value=='200':
                if failure=='interrupt-iso':raise KeyboardInterrupt
                raise TimeoutError('reply lost after applying ISO')
            return {'httpStatus':200,'body':{'code':200}}
        with patch.object(probe_module.capture_tool,'change_setting',side_effect=change):
            result=probe(frames,{},clock)
        return result,calls,state

    def test_success_restores_iso_and_filter_in_order(self):
        result,calls,state=self.run_fixture()
        self.assertNotIn('error',result)
        self.assertEqual(calls,[('ColorMode','Standard'),('ISO','200'),('ISO','100'),('ColorMode','HContrastBW')])
        self.assertEqual(result['restoration'],{'ISO':'metadata-confirmed','ColorMode':'metadata-confirmed'})
        self.assertFalse(result['restorationIncomplete'])
        self.assertEqual(state['ISOSetting'],'100')
        self.assertEqual(state['ColorMode'],'HContrastBW')

    def test_lost_reply_still_restores_applied_value(self):
        result,calls,state=self.run_fixture('lost-iso-reply')
        self.assertIn('error',result)
        self.assertEqual(calls.count(('ISO','200')),1)
        self.assertEqual(state['ISOSetting'],'100')
        self.assertEqual(result['restoration']['ISO'],'metadata-confirmed')

    def test_interrupt_still_restores_original_settings(self):
        result,calls,state=self.run_fixture('interrupt-iso')
        self.assertIn('KeyboardInterrupt',result['error'])
        self.assertEqual(state['ISOSetting'],'100')
        self.assertEqual(state['ColorMode'],'HContrastBW')

    def test_rejected_filter_does_not_attempt_iso_change(self):
        result,calls,state=self.run_fixture('reject-color')
        self.assertIn('error',result)
        self.assertFalse(any(field=='ISO' for field,value in calls))
        self.assertEqual(calls,[('ColorMode','Standard'),('ColorMode','HContrastBW')])

    def test_unconfirmed_restore_is_explicit(self):
        result,calls,state=self.run_fixture('restore-metadata-missing')
        self.assertTrue(result['restorationIncomplete'])
        self.assertTrue(result['restoration']['ISO'].startswith('not-confirmed'))
        self.assertEqual(result['restoration']['ColorMode'],'metadata-confirmed')

    def test_nonmanual_mode_sends_no_setters(self):
        result,calls,state=self.run_fixture(mode='P')
        self.assertIn('error',result)
        self.assertEqual(calls,[])

    def test_missing_complete_baseline_sends_no_iso_setter(self):
        result,calls,state=self.run_fixture(require_images=True)
        self.assertIn('No complete neutral baseline image',result['error'])
        self.assertFalse(any(field=='ISO' for field,value in calls))
        self.assertEqual(state['ColorMode'],'HContrastBW')

    def test_prefix_started_before_request_not_accepted_as_fresh(self):
        destination=ROOT/'output/exposure-probe-tests'/uuid.uuid4().hex
        destination.mkdir(parents=True)
        p=probe_module.Probe(destination,timeout=0.01,settle=0,min_frames=1,min_span=0,image_window=0)
        p.frames=queue.Queue()
        p.frames.put({'elapsedSeconds':2,'prefixStartedSeconds':0.5,'metadata':{'ExposureMode':'M'}})
        with self.assertRaises(TimeoutError):
            p.collect({'ExposureMode':'M'},after=1,initial=True)

    def test_invalid_setting_values_never_reach_transport(self):
        with patch.object(probe_module.capture_tool,'_http_payload') as transport:
            with self.assertRaises(ValueError):probe_module.capture_tool.change_setting('ISO','999999')
            with self.assertRaises(ValueError):probe_module.capture_tool.change_setting('ColorMode','INVALID')
            with self.assertRaises(ValueError):probe_module.capture_tool.change_setting('ShutterSpeed','1/100s')
        transport.assert_not_called()

    def test_valid_setting_payloads_come_from_upstream_builders(self):
        with patch.object(probe_module.capture_tool,'_http_payload',return_value={'httpStatus':200,'body':{'code':200}}) as transport:
            probe_module.capture_tool.change_setting('ISO','200',base='http://127.0.0.1')
            probe_module.capture_tool.change_setting('ColorMode','Standard',base='http://127.0.0.1')
        self.assertEqual(transport.call_args_list[0].args,({'command':'RCISOSet','ISO':'200'},'http://127.0.0.1'))
        self.assertEqual(transport.call_args_list[1].args,({'command':'RCChooseColorMode','ColorMode':'Standard'},'http://127.0.0.1'))

    def test_brightness_measurement_uses_same_mask(self):
        from PIL import Image
        destination=ROOT/'output/exposure-probe-tests'/uuid.uuid4().hex
        destination.mkdir(parents=True)
        phases=[]
        for label,value in [('baseline-standard',80),('higher-iso',160),('restored-iso-standard',80)]:
            name=label+'.png';Image.new('RGB',(8,8),(value,value,value)).save(destination/name)
            phases.append({'label':label,'frames':[{'file':name}]})
        analysis=probe_module.analyze(destination,{'phases':phases})
        self.assertEqual([x['medianMeanLuma'] for x in analysis['phases']],[80,160,80])


if __name__=='__main__':unittest.main()
