namespace Vault.Core
{
    partial class FileContainer : Container
    {
        public FileContainer(string file)
            : base(new FileStorage(file))
        {

        }
    }
}