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
      plugins: [
        {CredoContrib, []}
      ],
      checks: [
        {Credo.Check.Design.AliasUsage, false},
        {Credo.Check.Readability.MaxLineLength, max_length: 110},
        {Credo.Check.Refactor.MapInto, false},
        {Credo.Check.Warning.LazyLogging, false}
      ]
    }
  ]
}
