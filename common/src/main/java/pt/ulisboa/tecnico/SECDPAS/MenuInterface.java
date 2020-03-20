package pt.ulisboa.tecnico.SECDPAS;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;


public class MenuInterface {

    List<String> options;
    Scanner s;

    public MenuInterface(List<String> options){
        this.options = options;
        this.s = new Scanner(System.in);
    }

    public MenuInterface(){
        this.options = new ArrayList<String>();
        this.s = new Scanner(System.in);
    }

    public void addOption(String opt){

        options.add(opt);
    }

    public void showMenu(){

        int optMaxLength = 0;

        for(String o: options){
            if(o.length() > optMaxLength){
                optMaxLength = o.length();
            }
        }

        int numMaxLength = (int)Math.log10(options.size()) + 1;

        System.out.print(' ');
        printSeq(numMaxLength + 6, '_');
        System.out.print(' ');
        printSeq(optMaxLength + 4, '_');
        System.out.print('\n');

        for(int i = 0; i < options.size(); i++) {

            System.out.print('|');
            printSeq(numMaxLength + 6, ' ');
            System.out.print('|');
            printSeq(optMaxLength + 4, ' ');
            System.out.println('|');


            System.out.print('|');
            printSeq(3, ' ');
            System.out.print(i);
            printSeq(3, ' ');
            System.out.print('|');

            printSeq(2, ' ');
            System.out.print(options.get(i));
            printSeq(2 + optMaxLength - options.get(i).length(), ' ');
            System.out.println('|');


            System.out.print('|');
            printSeq(numMaxLength + 6, '_');
            System.out.print('|');
            printSeq(optMaxLength + 4, '_');
            System.out.println('|');
        }
    }

    public String selectOption(){

        int r = -1; 

        while(r < 0 || r >= options.size()){
            try {
                System.out.print("\nSelect an option: ");
                r = s.nextInt();

                if(r < 0 || r > options.size()){
                    System.out.println("Your option must be in the menu!");
                }
            } catch(Exception ignored){}
        }

        return options.get(r);
    }

    private void printSeq(int n, char c){
        for(int i = 0; i < n; i++){
            System.out.print(c);
        }
    }

}
