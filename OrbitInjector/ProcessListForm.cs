using System.Windows.Forms;

namespace OrbitInjector
{
    public partial class ProcessListForm : Form
    {
        public string ProcessName = string.Empty;
        public ProcessListForm()
        {
            InitializeComponent();
            this.Controls.Add(new ProcessListUC());
        }

        private void ProcessListForm_Load(object sender, System.EventArgs e)
        {
        }
    }
}

