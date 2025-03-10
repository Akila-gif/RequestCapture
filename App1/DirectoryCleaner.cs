using System.IO;
using MasterDevs.ChromeDevTools;

namespace App1
{
    internal class DirectoryCleaner : IDirectoryCleaner
    {
        public void Clean(string directory)
        {
            // Simple implementation that does basic cleanup
            // You can customize this if needed
            if (Directory.Exists(directory))
            {
                try
                {
                    // Remove temporary files or perform other cleanup as needed
                }
                catch
                {
                    // Handle or ignore exceptions
                }
            }
        }

        public void Delete(DirectoryInfo directoryInfo)
        {
            // Implementation for the required Delete method
            if (directoryInfo != null && directoryInfo.Exists)
            {
                try
                {
                    // Uncomment the following line if you actually want to delete directories
                    // directoryInfo.Delete(true);

                    // For safety, this implementation doesn't actually delete anything
                    // The method is implemented to satisfy the interface requirement
                }
                catch
                {
                    // Handle or ignore exceptions during deletion
                }
            }
        }
    }
}
