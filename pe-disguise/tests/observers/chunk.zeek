# Independent CHUNK DATA_EVENT consumer, including offsets.
module TestChunk;
global sizes: table[string] of count &default=0;
global calls: table[string] of count &default=0;
global contiguous: table[string] of bool &default=T;
global receive: event(f: fa_file, data: string, off: count);
event file_new(f: fa_file) &priority=-20
    { if ( f$source=="HTTP" ) Files::add_analyzer(f,Files::ANALYZER_DATA_EVENT,[$chunk_event=receive]); }
event receive(f: fa_file, data: string, off: count)
    {
    if ( off!=sizes[f$id] ) contiguous[f$id]=F;
    sizes[f$id] += |data|; ++calls[f$id];
    }
event file_state_remove(f: fa_file) &priority=-100
    {
    if ( f$source!="HTTP" ) return;
    local out=open_for_append("chunk.jsonl"); enable_raw_output(out);
    print out,cat(to_json([$fuid=f$id,$bytes=sizes[f$id],$callbacks=calls[f$id],$contiguous=contiguous[f$id],$seen=f$seen_bytes]),"\n");
    close(out);
    }
