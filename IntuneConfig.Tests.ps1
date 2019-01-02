$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
. "$here\$sut"

Describe "Check-PreReqs" {
    It 'Should say all pre-reqs met' { Check-PreReqs| Should -Be $True }
}

Describe "Check-Modules" {

    It 'should say true if module present' { Check-Modules | Should -Be $True }

}

Describe "Prompt-InstallAzureADModule" {
    Context "User chose yes" {
        Mock Prompt-InstallAzureADModule { return 'Yes'}
        }

}