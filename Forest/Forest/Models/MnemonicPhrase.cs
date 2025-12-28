using System;
using System.Collections.Generic;

public class MnemonicPhrase
{
    public List<string> MnemonicWords;
    public MnemonicPhrase()
    {
        MnemonicWords = new List<string>();
    }
    public MnemonicPhrase(List<string> MnemonicWords)
    {
        this.MnemonicWords = MnemonicWords;
    }
}