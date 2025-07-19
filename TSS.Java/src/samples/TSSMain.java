package samples;
//import java.util.Arrays;

import samples.CmdLine;
import samples.Samples;
//import tss.*;
//import tss.tpm.*;

public class TSSMain 
{
    
    public static void main(String[] args) 
    {
        CmdLine.setArgs(args);

        // DocSamples s1 = new DocSamples();
        // s1.doAll();
    
        System.out.println("TSSMain: starting Samples...");
        
        Samples s = new Samples();
        s.doAll(args);

        System.out.println("TSSMain: finished!");
        return;
    }
}
