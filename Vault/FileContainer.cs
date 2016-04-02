namespace Vault.Core
{
    partial class FileContainer<T> : Container<T>
    {
        public FileContainer(string file, Security<T> security)
            : base(new FileStorage(file), security)
        {

        }
    }
}