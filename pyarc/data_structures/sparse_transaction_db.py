from .appearance import Appearance
from .transaction import Transaction, UniqueTransaction
from . import Item
import progressbar

class SparseTransactionDB:
    
    def __init__(self, sparse_matrix, header, unique_transactions=True, drop_NaN=True):
        """TransactionDB represents a list of Transactions that can be
        passed to CBA algorithm as a training or a test set. 

        Parameters
        ----------
        
        dataset: two dimensional array of strings or ints
    
        header: array of strings
            Represents column labels.
        
        unique_transactions: bool
            Determines if UniqueTransaction or Transaction class
            should be used for individual instances.

        drop_NaN: bool
            Used for determining whether a an Item
            with NULL value should be dropped from Transaction


        Attributes
        ----------
        header: array of strings
            Column labels.

        class_labels: array of Items

        classes: array of strings
            Individual values of class_labels.

        data: array of Transactions
            Individual instances.

        string_representation: two dimensional array of strings
            e.g. [["food:=:schitzel", "mood:=:happy"], ["food:=:not_schitzel], ["mood:=:unhappy"]]


        """
        
        TransactionClass = UniqueTransaction if unique_transactions else Transaction
        
        self._dataset_param = dataset
        self.header = header
        self.class_labels = []
        
        new_dataset = []

        p = progressbar.ProgressBar()
        for row in p(dataset):
            class_label = Item(header[-1], row[-1])
            new_row = TransactionClass(row[:-1], header[:-1], class_label, drop_NaN=drop_NaN)
            
            self.class_labels.append(class_label)
            
            new_dataset.append(new_row)
            
        self.data = new_dataset
        self.classes = list(map(lambda i: i[1], self.class_labels))
        
        
        
        get_string_items = lambda transaction: transaction.string_items
        
        mapped = map(get_string_items, self)
        
        self.string_representation = list(mapped)
        
        

    @property
    def appeardict(self):
        """
        Returns
        -------
        an appearance dictionary to be used in the fim
        package. Assumes user wants to generate class association
        rules.
        """
        appear = Appearance()
        
        unique_class_items = set(self.class_labels)
        
        for item in unique_class_items:
            appear.add_to_RHS(item)

        return appear.dictionary


    @property
    def appeardict_itemsets_only(self):
        """
        Returns
        -------
        an appearance dictionary to be used in the fim
        package. Assumes user wants to generate frequent itemsets
        only, not class assocation rules
        """
        appear = Appearance()
        
        return appear.dictionary
        
    
    def __getitem__(self, idx):
        return self.data[idx]
    
    
    @classmethod
    def from_DataFrame(clazz, df, unique_transactions=False, drop_NaN=True):
        """
        Allows the conversion of pandas DataFrame class to 
        TransactionDB class.

        Parameters
        ----------
        
        df: pandas DataFrame
            A DataFrame from which to create a TransactionDB.
    
        unique_transactions: bool
            Determines if UniqueTransaction or Transaction class
            should be used for individual instances.

        drop_NaN: bool
            Used for determining whether a an Item
            with NULL value should be dropped from Transaction.
        """
        
        rows = df.values
        header = list(df.columns.values)

        return clazz(rows, header, unique_transactions=unique_transactions, drop_NaN=drop_NaN)

    
    def __repr__(self):
        return repr(self.string_representation)
        
    def __len__(self):
        return len(self.data)
        
