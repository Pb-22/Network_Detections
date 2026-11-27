# Independent STREAM DATA_EVENT consumer. Removal of the policy must spare it.
module TestStream;
global sizes: table[string] of count &default=0;
global calls: table[string] of count &default=0;
global receive: event(f: fa_file, data: string);
event file_new(f: fa_file) &priority=-20
    { if ( f$source=="HTTP" ) Files::add_analyzer(f,Files::ANALYZER_DATA_EVENT,[$stream_event=receive]); }
event receive(f: fa_file, data: string)
    { sizes[f$id] += |data|; ++calls[f$id]; }
event file_state_remove(f: fa_file) &priority=-100
    {
    if ( f$source!="HTTP" ) return;
    local out=open_for_append("stream.jsonl"); enable_raw_output(out);
    print out,cat(to_json([$fuid=f$id,$bytes=sizes[f$id],$callbacks=calls[f$id],$seen=f$seen_bytes]),"\n");
    close(out);
    }
