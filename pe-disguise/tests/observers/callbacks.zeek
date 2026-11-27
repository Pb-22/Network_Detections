# Test-only handler sharing the policy's callback; never load in production.
module PEFileDisguise;
global test_calls: table[string] of count &default=0;
global test_bytes: table[string] of count &default=0;
event prefix_data(f: fa_file, data: string) &priority=-100
    { ++test_calls[f$id]; test_bytes[f$id] += |data|; }
event zeek_done() &priority=-100
    {
    local out=open("callbacks.jsonl"); enable_raw_output(out);
    for ( id in test_calls )
        print out, cat(to_json([$fuid=id,$callbacks=test_calls[id],$bytes=test_bytes[id]]),"\n");
    local h=open("health.jsonl"); enable_raw_output(h);
    print h, cat(to_json(health),"\n");
    }
