from google.adk.events import Event
from google.genai import types

from control_panel.activity import ActivityTracker


def call_event(frame,call_id='0',partial=False,name='transfer_to_agent',author='specialist'):
    return Event(id=frame,author=author,partial=partial,content=types.Content(role='model',parts=[types.Part(function_call=types.FunctionCall(name=name,id=call_id,args={'agent_name':'coordinator'}))]))


def test_stream_fragments_and_replayed_final_event_count_once():
    tracker=ActivityTracker()
    entries=[]
    for index in range(6):
        entries.extend(tracker.events(call_event('partial'+str(index),partial=True)))
    completed=call_event('completed')
    entries.extend(tracker.events(completed))
    entries.extend(tracker.events(completed))
    response=Event(id='response',author='specialist',content=types.Content(role='user',parts=[types.Part(function_response=types.FunctionResponse(name='transfer_to_agent',id='0',response={'result':'ok'}))]))
    entries.extend(tracker.events(response))
    entries.extend(tracker.events(response))
    assert [e['label'] for e in entries]==['Working with specialist','Using transfer_to_agent','Finished transfer_to_agent']


def test_repeated_real_calls_and_parallel_calls_are_not_hidden():
    tracker=ActivityTracker()
    entries=tracker.events(call_event('first',name='brave_brave_web_search'))
    entries+=tracker.events(call_event('second',name='brave_brave_web_search'))
    parallel=call_event('parallel',name='brave_brave_web_search')
    parallel.content.parts.append(types.Part(function_call=types.FunctionCall(id='1',name='brave_brave_web_search',args={})))
    entries+=tracker.events(parallel)
    assert sum(e['label']=='Using brave_brave_web_search' for e in entries)==4


def test_incomplete_calls_are_ignored_even_without_partial_flag():
    event=call_event('unfinished')
    event.content.parts[0].function_call.will_continue=True
    assert [e['label'] for e in ActivityTracker().events(event)]==['Working with specialist']
