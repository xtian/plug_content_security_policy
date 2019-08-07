%{
  configs: [
    %{
      name: "default",
      color: true,
      strict: true,
      files: %{
        excluded: [
          ~r"/_build/",
          ~r"/deps/"
        ]
      },
      checks: [
        {Credo.Check.Design.AliasUsage, false},
        {Credo.Check.Readability.MaxLineLength, max_length: 110},
        {Credo.Check.Refactor.MapInto, false},
        {Credo.Check.Warning.LazyLogging, false},
        {CredoContrib.Check.DocWhitespace},
        {CredoContrib.Check.FunctionBlockSyntax},
        {CredoContrib.Check.ModuleAlias},
        {CredoContrib.Check.ModuleDirectivesOrder},
        {CredoContrib.Check.PublicPrivateFunctionName},
        {CredoContrib.Check.SingleFunctionPipe}
      ]
    }
  ]
}
